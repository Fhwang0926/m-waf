package manager

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Fhwang0926/m-waf/internal/crsindex"
	"github.com/Fhwang0926/m-waf/internal/localtime"
	"github.com/Fhwang0926/m-waf/internal/model"
	"github.com/Fhwang0926/m-waf/internal/policybundle"
	"github.com/Fhwang0926/m-waf/internal/systempolicy"
)

type systemPolicyMigrationRequest struct {
	ConfigSchemaVersion    int                            `json:"config_schema_version,omitempty"`
	Configuration          *PolicyConfiguration           `json:"configuration,omitempty"`
	ExpectedSystemPolicyID string                         `json:"expected_system_policy_id"`
	SourceID               string                         `json:"source_id"`
	Name                   string                         `json:"name"`
	Description            string                         `json:"description"`
	Mode                   string                         `json:"mode"`
	RequestBody            bool                           `json:"request_body"`
	ResponseBody           bool                           `json:"response_body"`
	CRSSetup               map[string]string              `json:"crs_setup"`
	ExcludedPaths          []string                       `json:"excluded_paths,omitempty"`
	ExcludedIPs            []string                       `json:"excluded_ips,omitempty"`
	BeforeExclusions       []systempolicy.RuleExclusion   `json:"before_crs_exclusions,omitempty"`
	AfterExclusions        []systempolicy.RuleExclusion   `json:"after_crs_exclusions,omitempty"`
	TagExclusions          []string                       `json:"tag_exclusions,omitempty"`
	TargetExclusions       []systempolicy.TargetExclusion `json:"target_exclusions,omitempty"`
	EngineBypasses         []systempolicy.EngineBypass    `json:"engine_bypasses,omitempty"`
	ServiceRules           string                         `json:"service_rules,omitempty"`
	MigrationNotes         []string                       `json:"migration_notes,omitempty"`
	ConfirmChangedRules    bool                           `json:"confirm_changed_rules"`
	ConfirmChannelChange   bool                           `json:"confirm_channel_change"`
	ConfirmLegacyBypass    bool                           `json:"confirm_legacy_bypass"`
	ValidationDigest       string                         `json:"validation_digest,omitempty"`
	PublishConfirm         bool                           `json:"publish_confirm,omitempty"`
	Action                 string                         `json:"action,omitempty"`
}

type migrationCompatibility struct {
	ServerID        string `json:"server_id"`
	ServerName      string `json:"server_name"`
	Compatible      bool   `json:"compatible"`
	Reason          string `json:"reason,omitempty"`
	AgentPackageID  string `json:"agent_package_id,omitempty"`
	ModulePackageID string `json:"module_package_id,omitempty"`
}

type migrationStrategyImpact struct {
	Automatic         int `json:"automatic"`
	Manual            int `json:"manual"`
	Pinned            int `json:"pinned"`
	MigrationRequired int `json:"migration_required"`
}

type systemPolicyMigrationValidation struct {
	Valid            bool                     `json:"valid"`
	FieldErrors      map[string]string        `json:"field_errors"`
	Warnings         []string                 `json:"warnings"`
	Candidate        systempolicy.Template    `json:"candidate"`
	RuleDiff         sourceRuleDiff           `json:"rule_diff"`
	SetupDiff        []sourceSetupDiff        `json:"setup_diff"`
	SourceSetupDiff  []sourceSetupDiff        `json:"source_setup_diff"`
	FileDiff         []sourceFileDiff         `json:"file_diff"`
	DirectiveDiff    []sourceDirectiveDiff    `json:"directive_diff"`
	Compatibility    []migrationCompatibility `json:"compatibility"`
	StrategyImpact   migrationStrategyImpact  `json:"strategy_impact"`
	ArtifactSHA256   string                   `json:"artifact_sha256,omitempty"`
	ValidationDigest string                   `json:"validation_digest,omitempty"`
}

type systemPolicyMigrationFieldError struct {
	Field   string
	Message string
}

func (e systemPolicyMigrationFieldError) Error() string { return e.Message }

func (s *Server) newSystemPolicyMigration(w http.ResponseWriter, r *http.Request) {
	base := s.defaultSystemPolicyTemplate(r.Context())
	selectedSourceID := strings.TrimSpace(r.URL.Query().Get("source_id"))
	s.renderSystemPolicyMigration(w, r, http.StatusOK, "", base, selectedSourceID, "", nil)
}

func (s *Server) renderSystemPolicyMigration(w http.ResponseWriter, r *http.Request, status int, pageError string, base systempolicy.Template, sourceID, validationDigest string, validation *systemPolicyMigrationValidation) {
	source, index, sourceFound, indexErr := s.indexedPolicySource(r.Context(), sourceID)
	if indexErr != nil && pageError == "" {
		pageError = "CRS DB 인덱스를 불러올 수 없습니다: " + indexErr.Error()
	}
	if !sourceFound && sourceID != "" && pageError == "" {
		pageError = "선택한 검증 CRS 소스를 찾을 수 없습니다. 목록에서 다시 선택하세요."
	}
	sources := make([]model.PolicySourceArtifact, 0, 1)
	if sourceFound {
		sources = append(sources, source)
	}
	setup := make([]crsindex.SetupField, len(index.Setup))
	copy(setup, index.Setup)
	setupValues := make(map[string]string, len(setup))
	for _, field := range setup {
		setupValues[field.Key] = field.Default
	}
	if base.Key == "" {
		for key, value := range map[string]string{
			"blocking_paranoia_level": "1", "detection_paranoia_level": "1",
			"inbound_anomaly_score_threshold": "5", "outbound_anomaly_score_threshold": "4",
		} {
			if _, supported := setupValues[key]; supported {
				setupValues[key] = value
			}
		}
	}
	for key, value := range base.Defaults.CRSSetup {
		setupValues[key] = value
	}
	inheritedSetupValues := make(map[string]string, len(setupValues))
	for key, value := range setupValues {
		inheritedSetupValues[key] = value
	}
	setupOverrides := make(map[string]bool, len(setupValues))
	baseID := ""
	if base.Key != "" {
		baseID = base.Reference()
	}
	nextVersion, versionErr := s.store.NextSystemPolicyVersion(r.Context())
	if versionErr != nil {
		nextVersion = "1.0.0"
		if pageError == "" {
			pageError = "다음 시스템 정책 개정본 번호를 확인할 수 없습니다."
		}
	}
	defaultName := base.Name
	if defaultName == "" {
		defaultName = "OWASP CRS " + source.Version + " 시스템 보호 정책"
	}
	defaultDescription := base.Description
	if defaultDescription == "" {
		defaultDescription = "검증된 OWASP CRS 원본에 M-WAF Setup과 공통 오버레이를 적용합니다."
	}
	defaultMode := base.Defaults.Mode
	if defaultMode == "" {
		defaultMode = "DetectionOnly"
	}
	data := map[string]any{
		"Error": pageError, "Base": base, "Sources": sources, "SelectedSourceID": sourceID,
		"BaseID": baseID, "HasBase": baseID != "", "HasSource": sourceFound, "SelectedSource": source, "Setup": setup, "SetupValues": setupValues, "NextVersion": nextVersion,
		"ChannelChange":    base.Key != "" && base.CRSTrack != "" && !strings.EqualFold(base.CRSTrack, source.Channel),
		"ValidationDigest": validationDigest, "Validation": validation, "BaseSetupValues": base.Defaults.CRSSetup,
		"InheritedSetupValues": inheritedSetupValues, "SetupOverrides": setupOverrides,
		"FormName": firstNonEmpty(r.FormValue("name"), defaultName), "FormDescription": firstNonEmpty(r.FormValue("description"), defaultDescription),
		"FormMode": firstNonEmpty(r.FormValue("mode"), defaultMode), "FormRequestBody": base.Key == "" || base.Defaults.RequestBody,
		"FormResponseBody":  base.Defaults.ResponseBody,
		"FormExcludedPaths": strings.Join(base.Defaults.ExcludedPaths, "\n"), "FormExcludedIPs": strings.Join(base.Defaults.ExcludedIPs, "\n"),
		"FormRuleExclusions": ruleExclusionLines(base.Defaults.AfterExclusions), "FormTargetExclusions": targetExclusionLines(base.Defaults.TargetExclusions, false),
		"FormTagExclusions":         strings.Join(base.Defaults.TagExclusions, "\n"),
		"FormConditionalExclusions": conditionalExclusionLines(base.Defaults.BeforeExclusions, base.Defaults.TargetExclusions),
		"FormServiceRules":          base.Defaults.CustomRules, "FormMigrationNotes": strings.Join(base.MigrationNotes, "\n"),
		"FormConfirmChanged":       false,
		"FormConfirmChannelChange": false,
		"FormConfirmLegacyBypass":  false,
		"FormBypassField":          "REQUEST_URI", "FormBypassOperator": "@beginsWith", "FormBypassExpiresAt": localtime.FormatKST(time.Now().Add(24*time.Hour), "2006-01-02T15:04"),
	}
	if s.catalog != nil {
		data["HotRuleSet"] = s.catalog.HotRuleSet()
	}
	if r.Method == http.MethodPost {
		data["FormRequestBody"] = r.FormValue("request_body") == "on"
		data["FormResponseBody"] = r.FormValue("response_body") == "on"
		for key := range setupValues {
			setupValues[key] = strings.TrimSpace(r.FormValue("setup." + key))
			setupOverrides[key] = r.FormValue("override."+key) == "on"
		}
		for key, formKey := range map[string]string{
			"FormExcludedPaths": "excluded_paths", "FormExcludedIPs": "excluded_ips", "FormRuleExclusions": "rule_exclusions",
			"FormTargetExclusions": "target_exclusions", "FormTagExclusions": "tag_exclusions", "FormConditionalExclusions": "conditional_exclusions",
			"FormServiceRules": "service_rules", "FormMigrationNotes": "migration_notes",
		} {
			data[key] = r.FormValue(formKey)
		}
		data["FormConfirmChanged"] = r.FormValue("confirm_changed_rules") == "confirmed"
		data["FormConfirmChannelChange"] = r.FormValue("confirm_channel_change") == "confirmed"
		data["FormConfirmLegacyBypass"] = r.FormValue("confirm_legacy_bypass") == "confirmed"
		data["FormBypassField"] = r.FormValue("bypass_field")
		data["FormBypassOperator"] = r.FormValue("bypass_operator")
		data["FormBypassValue"] = r.FormValue("bypass_value")
		data["FormBypassReason"] = r.FormValue("bypass_reason")
		data["FormBypassExpiresAt"] = r.FormValue("bypass_expires_at")
	}
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
	_ = s.templates.ExecuteTemplate(w, "system-policy-migration.html", s.viewData(r, "system-policies", data))
}

func (s *Server) apiValidateSystemPolicyMigration(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		writeProblem(w, http.StatusForbidden, "invalid csrf token")
		return
	}
	request, err := decodeSystemPolicyMigrationRequest(r)
	if err != nil {
		var fieldError systemPolicyMigrationFieldError
		if errors.As(err, &fieldError) {
			writeJSON(w, http.StatusUnprocessableEntity, systemPolicyMigrationValidation{FieldErrors: map[string]string{fieldError.Field: fieldError.Message}})
			return
		}
		writeProblem(w, http.StatusBadRequest, err.Error())
		return
	}
	validation := s.validateSystemPolicyMigration(r, request)
	status := http.StatusOK
	if !validation.Valid {
		status = http.StatusUnprocessableEntity
		if _, conflict := validation.FieldErrors["expected_system_policy_id"]; conflict {
			status = http.StatusConflict
		}
		s.audit(r, sessionFrom(r).Username, "system_policy.migration_blocked", request.SourceID, "failed")
	}
	writeJSON(w, status, validation)
}

func (s *Server) publishSystemPolicyMigration(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		s.renderAdminError(w, r, http.StatusForbidden, "보안 정보가 만료되었습니다", "화면을 새로고침한 뒤 다시 시도하세요.")
		return
	}
	request, err := decodeSystemPolicyMigrationRequest(r)
	if err != nil {
		base := s.defaultSystemPolicyTemplate(r.Context())
		s.renderSystemPolicyMigration(w, r, http.StatusBadRequest, err.Error(), base, r.FormValue("source_id"), "", nil)
		return
	}
	base := s.defaultSystemPolicyTemplate(r.Context())
	validation := s.validateSystemPolicyMigration(r, request)
	if !validation.Valid {
		s.audit(r, sessionFrom(r).Username, "system_policy.migration_blocked", request.SourceID, "failed")
		status := http.StatusUnprocessableEntity
		if _, conflict := validation.FieldErrors["expected_system_policy_id"]; conflict {
			status = http.StatusConflict
		}
		s.renderSystemPolicyMigration(w, r, status, "게시 전 검증에서 차단 항목이 발견되었습니다.", base, request.SourceID, "", &validation)
		return
	}
	if request.Action == "validate" {
		s.renderSystemPolicyMigration(w, r, http.StatusOK, "", base, request.SourceID, validation.ValidationDigest, &validation)
		return
	}
	if !request.PublishConfirm || request.ValidationDigest == "" || !strings.EqualFold(request.ValidationDigest, validation.ValidationDigest) {
		s.renderSystemPolicyMigration(w, r, http.StatusConflict, "검증 결과가 변경되었습니다. 다시 검증한 뒤 게시를 확인하세요.", base, request.SourceID, validation.ValidationDigest, &validation)
		return
	}
	if err := s.store.PublishSystemPolicyVersion(r.Context(), validation.Candidate, validation.Candidate.Defaults.CRSSource.Commit, request.ExpectedSystemPolicyID); err != nil {
		s.renderSystemPolicyMigration(w, r, http.StatusConflict, "시스템 정책을 게시할 수 없습니다: "+err.Error(), base, request.SourceID, "", &validation)
		return
	}
	session := sessionFrom(r)
	s.audit(r, session.Username, "system_policy.source_verified", request.SourceID+":"+validation.Candidate.Defaults.CRSSource.IndexSHA256, "success")
	s.audit(r, session.Username, "system_policy.publish", validation.Candidate.Reference(), "success")
	s.TriggerPolicySync()
	http.Redirect(w, r, systemPolicyPublishedURL(validation.Candidate), http.StatusSeeOther)
}

func systemPolicyPublishedURL(candidate systempolicy.Template) string {
	values := url.Values{}
	values.Set("published", candidate.Reference())
	values.Set("notice", "OWASP CRS "+candidate.CRSVersion+" 기반 시스템 정책을 게시했습니다.")
	return "/system-policies?" + values.Encode()
}

func decodeSystemPolicyMigrationRequest(r *http.Request) (systemPolicyMigrationRequest, error) {
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var request systemPolicyMigrationRequest
		decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil {
			return request, err
		}
		return normalizeMigrationRequest(request), nil
	}
	return systemPolicyMigrationRequestFromForm(r)
}

func systemPolicyMigrationRequestFromForm(r *http.Request) (systemPolicyMigrationRequest, error) {
	if err := r.ParseForm(); err != nil {
		return systemPolicyMigrationRequest{}, err
	}
	request := systemPolicyMigrationRequest{
		ExpectedSystemPolicyID: strings.TrimSpace(r.FormValue("expected_system_policy_id")), SourceID: strings.TrimSpace(r.FormValue("source_id")),
		Name: truncate(strings.TrimSpace(r.FormValue("name")), 255), Description: truncate(strings.TrimSpace(r.FormValue("description")), 1024),
		Mode: strings.TrimSpace(r.FormValue("mode")), RequestBody: r.FormValue("request_body") == "on", ResponseBody: r.FormValue("response_body") == "on",
		CRSSetup: map[string]string{}, ExcludedPaths: uniqueNonEmptyLines(r.FormValue("excluded_paths")), ExcludedIPs: uniqueNonEmptyLines(r.FormValue("excluded_ips")),
		TagExclusions: uniqueNonEmptyLines(r.FormValue("tag_exclusions")),
		ServiceRules:  r.FormValue("service_rules"), MigrationNotes: uniqueNonEmptyLines(r.FormValue("migration_notes")),
		ConfirmChangedRules:  r.FormValue("confirm_changed_rules") == "confirmed",
		ConfirmChannelChange: r.FormValue("confirm_channel_change") == "confirmed",
		ConfirmLegacyBypass:  r.FormValue("confirm_legacy_bypass") == "confirmed",
		ValidationDigest:     strings.TrimSpace(r.FormValue("validation_digest")), PublishConfirm: r.FormValue("publish_confirm") == "confirmed",
		Action: strings.TrimSpace(r.FormValue("action")),
	}
	for key, values := range r.Form {
		if strings.HasPrefix(key, "setup.") && len(values) != 0 {
			request.CRSSetup[strings.TrimPrefix(key, "setup.")] = strings.TrimSpace(values[0])
		}
	}
	after, err := parseRuleExclusions(r.FormValue("rule_exclusions"))
	if err != nil {
		return request, systemPolicyMigrationFieldError{Field: "rule_exclusions", Message: err.Error()}
	}
	targets, err := parseTargetExclusions(r.FormValue("target_exclusions"))
	if err != nil {
		return request, systemPolicyMigrationFieldError{Field: "target_exclusions", Message: err.Error()}
	}
	before, conditionalTargets, err := parseConditionalExclusions(r.FormValue("conditional_exclusions"))
	if err != nil {
		return request, systemPolicyMigrationFieldError{Field: "conditional_exclusions", Message: err.Error()}
	}
	request.AfterExclusions = after
	request.BeforeExclusions = before
	request.TargetExclusions = append(targets, conditionalTargets...)
	if bypassValue := strings.TrimSpace(r.FormValue("bypass_value")); bypassValue != "" {
		expiresAt, err := localtime.ParseKST("2006-01-02T15:04", strings.TrimSpace(r.FormValue("bypass_expires_at")))
		if err != nil {
			return request, systemPolicyMigrationFieldError{Field: "bypass_expires_at", Message: "긴급 우회 만료 시각을 입력하세요."}
		}
		request.EngineBypasses = append(request.EngineBypasses, systempolicy.EngineBypass{
			Reason: strings.TrimSpace(r.FormValue("bypass_reason")), ExpiresAt: expiresAt.UTC(),
			Conditions: []systempolicy.RuleCondition{{Field: strings.TrimSpace(r.FormValue("bypass_field")), Operator: strings.TrimSpace(r.FormValue("bypass_operator")), Value: bypassValue}},
		})
	}
	return normalizeMigrationRequest(request), nil
}

func normalizeMigrationRequest(request systemPolicyMigrationRequest) systemPolicyMigrationRequest {
	request.ExpectedSystemPolicyID = strings.TrimSpace(request.ExpectedSystemPolicyID)
	request.SourceID = strings.TrimSpace(request.SourceID)
	request.Name = truncate(strings.TrimSpace(request.Name), 255)
	request.Description = truncate(strings.TrimSpace(request.Description), 1024)
	request.Mode = strings.TrimSpace(request.Mode)
	request.ServiceRules = strings.TrimSpace(request.ServiceRules)
	request.ValidationDigest = strings.TrimSpace(request.ValidationDigest)
	request.Action = strings.TrimSpace(request.Action)
	for key, value := range request.CRSSetup {
		request.CRSSetup[strings.TrimSpace(key)] = strings.Join(strings.Fields(value), " ")
	}
	request.ExcludedPaths = uniqueStrings(request.ExcludedPaths)
	request.ExcludedIPs = uniqueStrings(request.ExcludedIPs)
	request.TagExclusions = uniqueStrings(request.TagExclusions)
	sort.Strings(request.TagExclusions)
	request.MigrationNotes = uniqueStrings(request.MigrationNotes)
	sort.Slice(request.AfterExclusions, func(i, j int) bool { return request.AfterExclusions[i].RuleID < request.AfterExclusions[j].RuleID })
	sort.Slice(request.BeforeExclusions, func(i, j int) bool { return request.BeforeExclusions[i].RuleID < request.BeforeExclusions[j].RuleID })
	sort.Slice(request.TargetExclusions, func(i, j int) bool {
		if request.TargetExclusions[i].RuleID == request.TargetExclusions[j].RuleID {
			return request.TargetExclusions[i].Target < request.TargetExclusions[j].Target
		}
		return request.TargetExclusions[i].RuleID < request.TargetExclusions[j].RuleID
	})
	return request
}

func applyStructuredSystemMigrationRequest(request *systemPolicyMigrationRequest, source model.PolicySourceArtifact, now time.Time) error {
	configuration := *request.Configuration
	configuration.SystemPolicyVersionID = "validation"
	configuration.PolicyRevisionID = ""
	if configuration.CRSReleaseID != "" && configuration.CRSReleaseID != source.ID {
		return errors.New("configuration의 CRS release가 선택한 source와 다릅니다")
	}
	configuration.CRSReleaseID = source.ID
	for _, value := range configuration.Setup {
		if value.SourceScope != PolicyScopeSystem {
			return errors.New("시스템 정책 configuration에는 SYSTEM scope Setup만 허용됩니다")
		}
	}
	for _, value := range configuration.Exclusions {
		if value.SourceScope != PolicyScopeSystem || value.Legacy {
			return errors.New("시스템 정책 configuration에는 신규 SYSTEM scope 예외만 허용됩니다")
		}
	}
	for _, value := range configuration.CustomRules {
		if value.SourceScope != PolicyScopeSystem {
			return errors.New("시스템 정책 configuration에는 SYSTEM scope Rule만 허용됩니다")
		}
	}
	if err := configuration.UpdateDigest(); err != nil {
		return err
	}
	if err := configuration.ValidateAt(now); err != nil {
		return err
	}
	request.Mode = configuration.EngineMode
	request.RequestBody = configuration.RequestBodyAccess
	request.ResponseBody = configuration.ResponseBodyAccess
	request.CRSSetup = configuration.CRSSetupMap()
	request.BeforeExclusions = nil
	request.AfterExclusions = nil
	request.TagExclusions = nil
	request.TargetExclusions = nil
	request.EngineBypasses = nil
	request.ServiceRules = ""
	for _, value := range configuration.Exclusions {
		conditions := make([]systempolicy.RuleCondition, 0, len(value.Conditions))
		for _, condition := range value.Conditions {
			conditions = append(conditions, systempolicy.RuleCondition{Field: condition.Field, Operator: condition.Operator, Value: condition.Value})
		}
		switch value.Type {
		case PolicyExclusionRule:
			exclusion := systempolicy.RuleExclusion{RuleID: value.RuleID, Conditions: conditions}
			if value.LoadStage == PolicyExclusionBefore {
				request.BeforeExclusions = append(request.BeforeExclusions, exclusion)
			} else {
				request.AfterExclusions = append(request.AfterExclusions, exclusion)
			}
		case PolicyExclusionTarget:
			request.TargetExclusions = append(request.TargetExclusions, systempolicy.TargetExclusion{RuleID: value.RuleID, Target: value.Target, Conditions: conditions})
		case PolicyExclusionTag:
			request.TagExclusions = append(request.TagExclusions, value.RuleTag)
		case PolicyExclusionEngineBypass:
			request.EngineBypasses = append(request.EngineBypasses, systempolicy.EngineBypass{Reason: value.Reason, ExpiresAt: *value.ExpiresAt, Conditions: conditions})
		}
	}
	var rules []string
	for _, value := range configuration.CustomRules {
		if value.Enabled {
			rules = append(rules, value.CanonicalSecRule)
		}
	}
	request.ServiceRules = strings.Join(rules, "\n")
	request.Configuration = &configuration
	return nil
}

func (s *Server) validateSystemPolicyMigration(r *http.Request, request systemPolicyMigrationRequest) systemPolicyMigrationValidation {
	result := systemPolicyMigrationValidation{FieldErrors: map[string]string{}}
	base := s.defaultSystemPolicyTemplate(r.Context())
	if request.ExpectedSystemPolicyID == "" {
		if base.Key != "" {
			result.FieldErrors["expected_system_policy_id"] = "다른 관리자가 최초 CRS 기준을 게시했습니다. 최신 상태를 다시 확인하세요."
			return result
		}
	} else {
		if base.Key == "" || base.Status != systempolicy.StatusPublished || base.Reference() != request.ExpectedSystemPolicyID {
			result.FieldErrors["expected_system_policy_id"] = "현재 게시 중인 기반 시스템 정책을 선택하세요."
			return result
		}
	}
	source, index, ok, sourceErr := s.indexedPolicySource(r.Context(), request.SourceID)
	if sourceErr != nil {
		result.FieldErrors["source_id"] = "검증된 CRS DB 인덱스를 불러올 수 없습니다."
		return result
	}
	if !ok {
		result.FieldErrors["source_id"] = "Manager가 검증·보존한 CRS 소스를 선택하세요."
		return result
	}
	if !source.TagSignatureVerified || source.TagObjectSHA == "" {
		result.FieldErrors["source_id"] = "annotated tag 서명이 검증된 CRS 소스만 게시할 수 있습니다."
		return result
	}
	if !request.ConfirmChangedRules {
		result.FieldErrors["confirm_changed_rules"] = "upstream Rule과 공통 예외의 변경 영향을 확인하세요."
	}
	if base.Key != "" {
		channelChange := !strings.EqualFold(source.Channel, base.CRSTrack)
		ref := base.Defaults.CRSSource
		legacyPinRepair := (ref == nil || ref.ID == "" || ref.ArchiveSHA256 == "" || ref.IndexSHA256 == "") && normalizeCRSVersion(source.Version) == normalizeCRSVersion(base.CRSVersion)
		samePinnedSource := exactSourceMatchesSystemPolicy(source, base)
		switch {
		case channelChange:
			result.Warnings = append(result.Warnings, fmt.Sprintf("CRS 채널을 %s에서 %s로 전환합니다. 버전 숫자보다 지원 주기와 Rule 차이를 기준으로 검토하세요.", strings.ToUpper(base.CRSTrack), strings.ToUpper(source.Channel)))
			if !request.ConfirmChannelChange {
				result.FieldErrors["confirm_channel_change"] = "LTS와 Stable 간 채널 전환 영향을 확인하세요."
			}
		case legacyPinRepair, samePinnedSource:
			// The CRS base stays fixed while the system override is reviewed again.
		case !newerCRSVersion(source.Version, base.CRSVersion):
			result.FieldErrors["source_id"] = "같은 채널에서는 현재 CRS보다 높은 검증 버전만 반영할 수 있습니다."
			return result
		}
	}
	request = normalizeMigrationRequest(request)
	if request.ConfigSchemaVersion == PolicyConfigStorageStructured {
		if request.Configuration == nil {
			result.FieldErrors["configuration"] = "config_schema_version 2에는 구조화 configuration이 필요합니다."
			return result
		}
		if len(request.ExcludedPaths) != 0 || len(request.ExcludedIPs) != 0 || len(request.BeforeExclusions) != 0 || len(request.AfterExclusions) != 0 || len(request.TagExclusions) != 0 || len(request.TargetExclusions) != 0 || len(request.EngineBypasses) != 0 || strings.TrimSpace(request.ServiceRules) != "" {
			result.FieldErrors["configuration"] = "구조화 configuration과 legacy 정책 필드를 함께 보낼 수 없습니다."
			return result
		}
		if err := applyStructuredSystemMigrationRequest(&request, source, time.Now().UTC()); err != nil {
			result.FieldErrors["configuration"] = err.Error()
			return result
		}
	} else if request.Configuration != nil {
		result.FieldErrors["configuration"] = "구조화 configuration에는 config_schema_version 2가 필요합니다."
		return result
	}
	var hotRuleVersion, hotRuleSHA string
	if s.catalog != nil {
		if hotRules := s.catalog.HotRuleSet(); hotRules != nil {
			hotRuleVersion, hotRuleSHA = hotRules.Version, hotRules.SHA256
			if strings.TrimSpace(hotRules.Rules) != "" && hotRules.Version != base.Defaults.HotRuleSetVersion {
				request.ServiceRules = strings.TrimSpace(strings.TrimSpace(request.ServiceRules) + "\n" + strings.TrimSpace(hotRules.Rules))
			}
		}
	}
	setup, setupErrors := validateMigrationSetup(index.Setup, request.CRSSetup)
	if parseSetupInt(setup, "detection_paranoia_level") < parseSetupInt(setup, "blocking_paranoia_level") {
		setupErrors["detection_paranoia_level"] = "탐지 Paranoia Level은 차단 실행 Level보다 낮을 수 없습니다."
	}
	maxFileUnlimited := strings.EqualFold(setup["max_file_size"], "unlimited")
	combinedFileUnlimited := strings.EqualFold(setup["combined_file_sizes"], "unlimited")
	if maxFileUnlimited && !combinedFileUnlimited || !maxFileUnlimited && !combinedFileUnlimited && parseSetupInt(setup, "combined_file_sizes") < parseSetupInt(setup, "max_file_size") {
		setupErrors["combined_file_sizes"] = "전체 파일 제한은 단일 파일 제한보다 작을 수 없습니다."
	}
	for key, message := range setupErrors {
		result.FieldErrors["crs_setup."+key] = message
	}
	request.CRSSetup = setup
	if request.Name == "" {
		result.FieldErrors["name"] = "시스템 정책 이름을 입력하세요."
	}
	if request.Mode != "DetectionOnly" && request.Mode != "On" {
		result.FieldErrors["mode"] = "탐지만 또는 차단 모드를 선택하세요."
	}
	_, settingsJSON, artifactErr := buildManagedPolicyArtifact(request.Mode, parseSetupInt(setup, "blocking_paranoia_level"), parseSetupInt(setup, "inbound_anomaly_score_threshold"), request.RequestBody, strings.Join(request.ExcludedPaths, "\n"), strings.Join(request.ExcludedIPs, "\n"), request.ServiceRules, ManagedPolicyMetadata{})
	if artifactErr != nil {
		result.FieldErrors["policy"] = artifactErr.Error()
	}
	if (len(request.ExcludedPaths) != 0 || len(request.ExcludedIPs) != 0) && !request.ConfirmLegacyBypass {
		result.FieldErrors["confirm_legacy_bypass"] = "기존 URL/IP 예외는 전체 WAF 검사를 우회합니다. 유지 여부를 명시적으로 확인하세요."
	}
	for _, bypass := range request.EngineBypasses {
		if strings.TrimSpace(bypass.Reason) == "" || len(bypass.Conditions) == 0 {
			result.FieldErrors["engine_bypasses"] = "긴급 전체 우회에는 사유와 조건이 필요합니다."
			continue
		}
		if bypass.ExpiresAt.Before(time.Now().UTC()) || bypass.ExpiresAt.After(time.Now().UTC().Add(7*24*time.Hour)) {
			result.FieldErrors["engine_bypasses"] = "긴급 전체 우회 만료는 지금부터 7일 이내여야 합니다."
		}
		if err := validateRuleConditions(bypass.Conditions); err != nil {
			result.FieldErrors["engine_bypasses"] = err.Error()
		}
	}
	var normalizedSettings PolicySettings
	if settingsJSON != "" {
		_ = json.Unmarshal([]byte(settingsJSON), &normalizedSettings)
	}
	if err := validateCustomRuleScopeIDs(normalizedSettings.CustomRules, PolicyScopeSystem); err != nil {
		result.FieldErrors["service_rules"] = "새 시스템 정책의 공통 Rule ID는 10000..39999를 사용해야 합니다. 기존 240000..249999 Rule은 현재 성공본과 롤백에서만 보존됩니다."
	}
	rules := make(map[int]crsindex.Rule, len(index.Rules))
	tags := make(map[string]bool)
	for _, rule := range index.Rules {
		rules[rule.ID] = rule
		for _, tag := range rule.Tags {
			tags[tag] = true
		}
	}
	validateMigrationExclusions(result.FieldErrors, rules, request)
	for _, tag := range request.TagExclusions {
		if !tags[tag] {
			result.FieldErrors["tag_exclusions"] = "대상 CRS에 없는 Rule tag가 포함되어 있습니다: " + tag
		}
	}
	baseID := ""
	if base.Key != "" {
		baseID = base.Reference()
	}
	diff, _, _ := s.openSourceDiff(r, source.ID, baseID)
	result.RuleDiff, result.SetupDiff = diff.Rules, diff.Setup
	result.SourceSetupDiff, result.FileDiff, result.DirectiveDiff = diff.SourceSetup, diff.Files, diff.Directives
	setupChanges := make(map[string]bool, len(result.SetupDiff))
	for _, change := range result.SetupDiff {
		setupChanges[change.Key] = true
	}
	for key, nextValue := range setup {
		if previousValue, exists := base.Defaults.CRSSetup[key]; exists && previousValue != nextValue && !setupChanges[key] {
			result.SetupDiff = append(result.SetupDiff, sourceSetupDiff{Key: key, Change: "VALUE_CHANGED", Previous: previousValue, Next: nextValue})
		}
	}
	sort.Slice(result.SetupDiff, func(i, j int) bool { return result.SetupDiff[i].Key < result.SetupDiff[j].Key })
	for _, change := range result.SetupDiff {
		if _, configured := base.Defaults.CRSSetup[change.Key]; configured && (change.Change == "REMOVED" || change.Change == "TYPE_CHANGED") {
			result.FieldErrors["crs_setup."+change.Key] = "기존 시스템 정책이 사용하는 Setup 키가 제거되었거나 타입이 변경되었습니다. 명시적인 대체 설정 없이는 게시할 수 없습니다."
		}
	}
	changed := make(map[int]bool)
	for _, rule := range diff.Rules.Changed {
		changed[rule.ID] = true
	}
	changedReference := false
	for _, id := range migrationReferencedRuleIDs(request) {
		if changed[id] {
			changedReference = true
			result.Warnings = append(result.Warnings, fmt.Sprintf("내용이 변경된 upstream Rule %d을 오버레이가 참조합니다.", id))
		}
	}
	if changedReference && !request.ConfirmChangedRules {
		result.FieldErrors["confirm_changed_rules"] = "변경된 Rule 참조를 검토하고 명시적으로 확인하세요."
	}
	result.Compatibility = s.validateMigrationCompatibility(r, source)
	if source.ArtifactFormat != policybundle.FormatV3 && !s.policySourceHasV2Coverage(source) {
		result.FieldErrors["compatibility"] = "선택한 CRS 소스의 Agent v2와 Apache/Nginx distro·external 패키지 구성이 현재 번들에 없습니다."
	}
	for _, item := range result.Compatibility {
		if !item.Compatible {
			result.FieldErrors["compatibility"] = "호환 패키지 또는 롤백 패키지가 없는 활성 서버가 있습니다."
			break
		}
	}
	policies, err := s.store.ListEnterprisePolicies(r.Context(), "", systemPolicyServerLimit)
	if err != nil {
		result.FieldErrors["enterprise_impact"] = "기업 정책 영향 범위를 불러올 수 없습니다."
	} else {
		removedOrChanged := make(map[int]bool)
		for _, rule := range append(append([]crsindex.Rule(nil), diff.Rules.Removed...), diff.Rules.Changed...) {
			removedOrChanged[rule.ID] = true
		}
		for _, policy := range policies {
			requiresMigration := len(policy.CurrentSettings.ExcludedPaths) != 0 || len(policy.CurrentSettings.ExcludedIPs) != 0
			for _, exclusion := range policy.CurrentSettings.Exclusions {
				if removedOrChanged[exclusion.RuleID] {
					requiresMigration = true
				}
			}
			for _, match := range customRuleID.FindAllStringSubmatch(policy.CurrentSettings.CustomRules, -1) {
				id, _ := strconv.Atoi(match[1])
				if isLegacyPolicyRuleID(id) || rules[id].ID != 0 {
					requiresMigration = true
				}
			}
			if requiresMigration {
				result.StrategyImpact.MigrationRequired++
			}
			switch policy.UpdateStrategy {
			case PolicyStrategyAutomatic:
				result.StrategyImpact.Automatic++
			case PolicyStrategyManual:
				result.StrategyImpact.Manual++
			case PolicyStrategyPinned:
				result.StrategyImpact.Pinned++
			}
		}
	}
	ref := systempolicy.PolicySourceRef{ID: source.ID, Repository: source.Repository, Channel: source.Channel, Tag: source.Tag, Commit: source.Commit, TagObjectSHA: source.TagObjectSHA, TagVerified: source.TagSignatureVerified, ArchiveSHA256: source.ArchiveSHA256, IndexSHA256: source.IndexSHA256}
	blockingPL := parseSetupInt(setup, "blocking_paranoia_level")
	executingPL := parseSetupInt(setup, "detection_paranoia_level")
	if executingPL == 0 {
		executingPL = blockingPL
	}
	outboundScore := parseSetupInt(setup, "outbound_anomaly_score_threshold")
	if outboundScore == 0 {
		outboundScore = 4
	}
	samplingPercentage := parseSetupInt(setup, "sampling_percentage")
	if samplingPercentage == 0 {
		samplingPercentage = 100
	}
	policyVersion, versionErr := s.store.NextSystemPolicyVersion(r.Context())
	if versionErr != nil {
		result.FieldErrors["candidate"] = "다음 시스템 정책 개정본 번호를 확인할 수 없습니다."
		return result
	}
	artifactFormat := source.ArtifactFormat
	if artifactFormat == "" {
		artifactFormat = policybundle.Format
	}
	result.Candidate = systempolicy.Template{
		SchemaVersion: 2, Key: systempolicy.DefaultTemplateKey, Version: policyVersion, Name: request.Name, Description: request.Description,
		CRSTrack: source.Channel, CRSVersion: source.Version, Status: systempolicy.StatusPublished,
		Defaults: systempolicy.Defaults{
			Mode: request.Mode, ParanoiaLevel: blockingPL, ExecutingParanoiaLevel: executingPL,
			InboundScore: parseSetupInt(setup, "inbound_anomaly_score_threshold"), OutboundScore: outboundScore,
			RequestBody: request.RequestBody, ResponseBody: request.ResponseBody, EarlyBlocking: parseSetupInt(setup, "early_blocking") == 1,
			SamplingPercentage: samplingPercentage, ExcludedPaths: normalizedSettings.ExcludedPaths, ExcludedIPs: normalizedSettings.ExcludedIPs,
			CustomRules: normalizedSettings.CustomRules, CustomRuleCount: normalizedSettings.CustomRuleCount,
			CRSSource: &ref, CRSSetup: setup, BeforeExclusions: request.BeforeExclusions, AfterExclusions: request.AfterExclusions,
			TagExclusions: request.TagExclusions, TargetExclusions: request.TargetExclusions, EngineBypasses: request.EngineBypasses, ArtifactFormat: artifactFormat,
			HotRuleSetVersion: hotRuleVersion, HotRuleSetSHA256: hotRuleSHA,
		},
		MigrationNotes: request.MigrationNotes,
	}
	if err := result.Candidate.Validate(); err != nil {
		result.FieldErrors["candidate"] = err.Error()
	}
	configurationSettings := PolicySettings{
		ParanoiaLevel: blockingPL, ExecutingParanoiaLevel: executingPL, InboundScore: parseSetupInt(setup, "inbound_anomaly_score_threshold"),
		OutboundScore: outboundScore, RequestBody: request.RequestBody, ResponseBody: request.ResponseBody,
		EarlyBlocking: parseSetupInt(setup, "early_blocking") == 1, SamplingPercentage: samplingPercentage,
	}
	configuration, _, configurationErr := structuredConfigurationFromPolicy(result.Candidate.Reference(), "", result.Candidate, request.Mode, configurationSettings)
	if configurationErr == nil {
		configurationErr = validateConfigurationRuleIDs(configuration, index)
	}
	if configurationErr != nil {
		result.FieldErrors["configuration"] = configurationErr.Error()
	}
	bundleInput := policyBundleInputFromConfiguration(configuration)
	var artifact []byte
	if artifactFormat == policybundle.FormatV3 {
		files, filesErr := s.policySourceFiles(source.ID)
		if filesErr != nil {
			err = filesErr
		} else {
			artifact, _, err = policybundle.BuildWithCRS(ref, bundleInput, files)
		}
	} else {
		artifact, _, err = policybundle.Build(ref, bundleInput)
	}
	if err != nil {
		result.FieldErrors["artifact"] = err.Error()
	} else {
		digest := sha256.Sum256(artifact)
		result.ArtifactSHA256 = hex.EncodeToString(digest[:])
	}
	result.Valid = len(result.FieldErrors) == 0
	if result.Valid {
		canonical := struct {
			Candidate     systempolicy.Template    `json:"candidate"`
			Compatibility []migrationCompatibility `json:"compatibility"`
			Artifact      string                   `json:"artifact_sha256"`
		}{result.Candidate, result.Compatibility, result.ArtifactSHA256}
		raw, _ := json.Marshal(canonical)
		digest := sha256.Sum256(raw)
		result.ValidationDigest = hex.EncodeToString(digest[:])
		candidateRaw, _ := json.Marshal(result.Candidate)
		templateDigest := sha256.Sum256(candidateRaw)
		result.Candidate.Digest = hex.EncodeToString(templateDigest[:])
	}
	return result
}

func (s *Server) policySourceHasV2Coverage(source model.PolicySourceArtifact) bool {
	agent := false
	modules := map[string]bool{}
	for _, id := range source.CompatiblePackageIDs {
		artifact, ok := s.catalog.Artifact(id)
		if !ok {
			continue
		}
		if artifact.Kind == "agent" && containsString(artifact.PolicyFormats, policybundle.Format) {
			agent = true
		}
		if artifact.Kind == "module" {
			modules[artifact.WebServer+":"+model.NormalizeIntegrationMode(artifact.IntegrationMode)] = true
		}
	}
	return agent && modules["apache:distro"] && modules["apache:external"] && modules["nginx:distro"] && modules["nginx:external"]
}

func validateMigrationSetup(fields []crsindex.SetupField, values map[string]string) (map[string]string, map[string]string) {
	normalized := make(map[string]string, len(fields))
	errorsByKey := map[string]string{}
	supported := make(map[string]crsindex.SetupField, len(fields))
	for _, field := range fields {
		supported[field.Key] = field
		value := strings.Join(strings.Fields(values[field.Key]), " ")
		if value == "" {
			value = field.Default
		}
		if field.Type == "integer" {
			if setupValueAllowsUnlimited(field.Key) && strings.EqualFold(value, "unlimited") {
				normalized[field.Key] = "unlimited"
				continue
			}
			number, err := strconv.Atoi(value)
			if err != nil || number < field.Minimum || number > field.Maximum {
				message := fmt.Sprintf("%d..%d 범위의 숫자를 입력하세요.", field.Minimum, field.Maximum)
				if setupValueAllowsUnlimited(field.Key) {
					message = fmt.Sprintf("%d..%d 범위의 숫자 또는 unlimited를 입력하세요.", field.Minimum, field.Maximum)
				}
				errorsByKey[field.Key] = message
				continue
			}
		} else {
			if strings.ContainsAny(value, "'\"\\\r\n") {
				errorsByKey[field.Key] = "따옴표, 역슬래시나 줄바꿈 없이 공백으로 구분해 입력하세요."
				continue
			}
			if len(field.Options) != 0 && !containsString(field.Options, value) {
				errorsByKey[field.Key] = "허용된 값 중 하나를 선택하세요."
				continue
			}
		}
		normalized[field.Key] = value
	}
	for key := range values {
		if _, ok := supported[key]; !ok {
			errorsByKey[key] = "대상 CRS에서 지원하지 않는 Setup 키입니다."
		}
	}
	return normalized, errorsByKey
}

func validateMigrationExclusions(fieldErrors map[string]string, rules map[int]crsindex.Rule, request systemPolicyMigrationRequest) {
	for _, exclusion := range append(append([]systempolicy.RuleExclusion(nil), request.BeforeExclusions...), request.AfterExclusions...) {
		if _, ok := rules[exclusion.RuleID]; !ok {
			fieldErrors["rule_exclusions"] = fmt.Sprintf("대상 CRS에 Rule %d이 없습니다. 제외를 삭제하거나 새 Rule로 명시적으로 교체하세요.", exclusion.RuleID)
		}
		if err := validateRuleConditions(exclusion.Conditions); err != nil {
			fieldErrors["conditional_exclusions"] = err.Error()
		}
	}
	for _, exclusion := range request.TargetExclusions {
		rule, ok := rules[exclusion.RuleID]
		if !ok {
			fieldErrors["target_exclusions"] = fmt.Sprintf("대상 CRS에 Rule %d이 없습니다.", exclusion.RuleID)
			continue
		}
		if !ruleHasTarget(rule, exclusion.Target) {
			fieldErrors["target_exclusions"] = fmt.Sprintf("Rule %d은 변수 %s를 사용하지 않습니다.", exclusion.RuleID, exclusion.Target)
		}
		if err := validateRuleConditions(exclusion.Conditions); err != nil {
			fieldErrors["conditional_exclusions"] = err.Error()
		}
	}
}

func validateRuleConditions(conditions []systempolicy.RuleCondition) error {
	allowedFields := map[string]bool{"REQUEST_URI": true, "REQUEST_METHOD": true, "REQUEST_HEADERS:Host": true, "REMOTE_ADDR": true}
	allowedOperators := map[string]bool{"@beginsWith": true, "@streq": true, "@ipMatch": true}
	for _, condition := range conditions {
		if !allowedFields[condition.Field] || !allowedOperators[condition.Operator] || condition.Value == "" || strings.ContainsAny(condition.Value, "\"\r\n") {
			return errors.New("조건부 예외는 허용된 요청 필드·연산자와 한 줄 값을 사용하세요.")
		}
	}
	return nil
}

func ruleHasTarget(rule crsindex.Rule, target string) bool {
	base := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(target), "!"), "&")
	base = strings.SplitN(base, ":", 2)[0]
	for _, variable := range rule.Variables {
		candidate := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(variable), "!"), "&")
		if strings.SplitN(candidate, ":", 2)[0] == base {
			return true
		}
	}
	return false
}

func (s *Server) validateMigrationCompatibility(r *http.Request, source model.PolicySourceArtifact) []migrationCompatibility {
	servers, err := s.store.ListServers(r.Context(), "", systemPolicyServerLimit)
	if err != nil {
		return []migrationCompatibility{{Compatible: false, Reason: "활성 서버 목록을 불러올 수 없습니다."}}
	}
	compatibleIDs := make(map[string]bool, len(source.CompatiblePackageIDs))
	for _, id := range source.CompatiblePackageIDs {
		compatibleIDs[id] = true
	}
	items := make([]migrationCompatibility, 0, len(servers))
	for _, server := range servers {
		if server.Revoked || !serverReadyForPolicyCompatibility(server) {
			continue
		}
		item := migrationCompatibility{ServerID: server.ID, ServerName: server.Name}
		if source.ArtifactFormat == policybundle.FormatV3 {
			switch {
			case !containsString(server.Inventory.PolicyFormats, policybundle.FormatV3) || !serverSupportsSplitPolicy(server):
				item.Reason = "Agent가 기본 정책과 기업 오버라이드 분리 형식을 지원하지 않습니다."
			case !server.Inventory.ConnectorLoaded:
				item.Reason = "ModSecurity Connector 로드 상태를 확인할 수 없습니다."
			case !server.Inventory.ConfigTestOK:
				item.Reason = "웹서버 configtest가 통과하지 않았습니다."
			case server.Inventory.InstallationMode == "manual":
				item.Compatible = true
			case s.catalog == nil:
				item.Reason = "서명된 Agent·모듈 package bundle을 사용할 수 없습니다."
			default:
				agentPackage, modulePackage, resolveErr := s.catalog.Resolve(server.Inventory)
				if resolveErr != nil {
					item.Reason = "현재 OS·아키텍처·웹서버에 맞는 Agent·모듈 패키지가 없습니다: " + resolveErr.Error()
					break
				}
				item.AgentPackageID, item.ModulePackageID = agentPackage.ID, modulePackage.ID
				if agentPackage.RollbackID == "" || modulePackage.RollbackID == "" {
					item.Reason = "Agent 또는 모듈 롤백 패키지가 없습니다."
				} else if _, ok := s.catalog.Artifact(agentPackage.RollbackID); !ok {
					item.Reason = "Agent 롤백 패키지를 검증할 수 없습니다."
				} else if _, ok := s.catalog.Artifact(modulePackage.RollbackID); !ok {
					item.Reason = "모듈 롤백 패키지를 검증할 수 없습니다."
				} else {
					item.Compatible = true
				}
			}
			items = append(items, item)
			continue
		}
		if server.Inventory.InstallationMode == "manual" {
			item.Reason = "수동 Connector 서버는 self-contained policy-bundle-v3 정책만 지원합니다."
			items = append(items, item)
			continue
		}
		agentPackage, modulePackage, resolveErr := s.catalog.ResolveCRS(server.Inventory, source.Version)
		if resolveErr != nil {
			item.Reason = resolveErr.Error()
			items = append(items, item)
			continue
		}
		item.AgentPackageID, item.ModulePackageID = agentPackage.ID, modulePackage.ID
		if !compatibleIDs[agentPackage.ID] || !compatibleIDs[modulePackage.ID] {
			item.Reason = "정책 소스가 허용한 패키지 조합이 아닙니다."
		} else if !containsString(agentPackage.PolicyFormats, policybundle.Format) {
			item.Reason = "Agent 패키지가 policy-bundle-v2를 지원하지 않습니다."
		} else if agentPackage.RollbackID == "" || modulePackage.RollbackID == "" {
			item.Reason = "Agent 또는 모듈 롤백 패키지가 없습니다."
		} else if _, ok := s.catalog.Artifact(agentPackage.RollbackID); !ok {
			item.Reason = "Agent 롤백 패키지를 검증할 수 없습니다."
		} else if _, ok := s.catalog.Artifact(modulePackage.RollbackID); !ok {
			item.Reason = "모듈 롤백 패키지를 검증할 수 없습니다."
		} else {
			item.Compatible = true
		}
		items = append(items, item)
	}
	return items
}

func serverReadyForPolicyCompatibility(server ServerRecord) bool {
	if server.Inventory.InstallationStage != "" {
		return server.Inventory.InstallationStage == model.InstallationStageProtected
	}
	return server.Inventory.ConnectorLoaded && server.Inventory.ConfigTestOK
}

func (s *Server) catalogPolicySources() []model.PolicySourceArtifact {
	return s.allPolicySources()
}

func parseRuleExclusions(text string) ([]systempolicy.RuleExclusion, error) {
	items := make([]systempolicy.RuleExclusion, 0)
	for _, value := range splitList(text) {
		id, err := strconv.Atoi(value)
		if err != nil || id <= 0 {
			return nil, fmt.Errorf("올바르지 않은 Rule ID %q", value)
		}
		items = append(items, systempolicy.RuleExclusion{RuleID: id})
	}
	return items, nil
}

func parseTargetExclusions(text string) ([]systempolicy.TargetExclusion, error) {
	items := make([]systempolicy.TargetExclusion, 0)
	for _, line := range uniqueNonEmptyLines(text) {
		parts := strings.Split(line, "|")
		if len(parts) != 2 {
			return nil, errors.New("Target 제외는 RuleID|변수 형식으로 입력하세요.")
		}
		id, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		target := strings.TrimSpace(parts[1])
		if err != nil || id <= 0 || target == "" || strings.ContainsAny(target, "\"'\r\n ") {
			return nil, errors.New("Target 제외의 Rule ID와 변수를 확인하세요.")
		}
		items = append(items, systempolicy.TargetExclusion{RuleID: id, Target: target})
	}
	return items, nil
}

func parseConditionalExclusions(text string) ([]systempolicy.RuleExclusion, []systempolicy.TargetExclusion, error) {
	var rules []systempolicy.RuleExclusion
	var targets []systempolicy.TargetExclusion
	for _, line := range uniqueNonEmptyLines(text) {
		parts := strings.Split(line, "|")
		if len(parts) != 5 {
			return nil, nil, errors.New("조건부 예외는 RuleID|Target(선택)|요청필드|연산자|값 형식으로 입력하세요.")
		}
		id, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil || id <= 0 {
			return nil, nil, errors.New("조건부 예외의 Rule ID를 확인하세요.")
		}
		condition := systempolicy.RuleCondition{Field: strings.TrimSpace(parts[2]), Operator: strings.TrimSpace(parts[3]), Value: strings.TrimSpace(parts[4])}
		if target := strings.TrimSpace(parts[1]); target != "" {
			targets = append(targets, systempolicy.TargetExclusion{RuleID: id, Target: target, Conditions: []systempolicy.RuleCondition{condition}})
		} else {
			rules = append(rules, systempolicy.RuleExclusion{RuleID: id, Conditions: []systempolicy.RuleCondition{condition}})
		}
	}
	return rules, targets, nil
}

func splitList(text string) []string {
	return uniqueStrings(strings.FieldsFunc(text, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' || r == ' ' || r == '\t' }))
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

func parseSetupInt(values map[string]string, key string) int {
	value, _ := strconv.Atoi(values[key])
	return value
}

func migrationReferencedRuleIDs(request systemPolicyMigrationRequest) []int {
	seen := map[int]bool{}
	for _, item := range request.BeforeExclusions {
		seen[item.RuleID] = true
	}
	for _, item := range request.AfterExclusions {
		seen[item.RuleID] = true
	}
	for _, item := range request.TargetExclusions {
		seen[item.RuleID] = true
	}
	result := make([]int, 0, len(seen))
	for id := range seen {
		result = append(result, id)
	}
	sort.Ints(result)
	return result
}

func ruleExclusionLines(items []systempolicy.RuleExclusion) string {
	values := make([]string, 0)
	for _, item := range items {
		if len(item.Conditions) == 0 {
			values = append(values, strconv.Itoa(item.RuleID))
		}
	}
	return strings.Join(values, "\n")
}

func targetExclusionLines(items []systempolicy.TargetExclusion, conditional bool) string {
	values := make([]string, 0)
	for _, item := range items {
		if (len(item.Conditions) != 0) != conditional {
			continue
		}
		values = append(values, fmt.Sprintf("%d|%s", item.RuleID, item.Target))
	}
	return strings.Join(values, "\n")
}

func conditionalExclusionLines(rules []systempolicy.RuleExclusion, targets []systempolicy.TargetExclusion) string {
	values := make([]string, 0)
	for _, item := range rules {
		for _, condition := range item.Conditions {
			values = append(values, fmt.Sprintf("%d||%s|%s|%s", item.RuleID, condition.Field, condition.Operator, condition.Value))
		}
	}
	for _, item := range targets {
		for _, condition := range item.Conditions {
			values = append(values, fmt.Sprintf("%d|%s|%s|%s|%s", item.RuleID, item.Target, condition.Field, condition.Operator, condition.Value))
		}
	}
	return strings.Join(values, "\n")
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
