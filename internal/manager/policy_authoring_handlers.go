package manager

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Fhwang0926/m-waf/internal/localtime"
	"github.com/Fhwang0926/m-waf/internal/systempolicy"
)

type guidedPolicyRule struct {
	Field    string `json:"field"`
	Argument string `json:"argument,omitempty"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
	Action   string `json:"action"`
}

var guidedPolicyRuleLine = regexp.MustCompile(`^SecRule ([A-Za-z0-9:_-]+) "(@streq|@beginsWith|@contains) ([^"\\\r\n]+)" "id:([0-9]+),phase:1,(pass,log|deny,status:403,log),msg:M-WAF guided rule [0-9]+"$`)

type policyValidationRequest struct {
	ConfigSchemaVersion    int                `json:"config_schema_version,omitempty"`
	PolicyID               string             `json:"policy_id"`
	ExpectedRevision       string             `json:"expected_revision_id"`
	TemplateKey            string             `json:"template_key"`
	Name                   string             `json:"name"`
	Description            string             `json:"description"`
	Target                 string             `json:"target"`
	Mode                   string             `json:"mode"`
	ParanoiaLevel          int                `json:"paranoia_level"`
	InboundScore           int                `json:"inbound_score"`
	RequestBody            bool               `json:"request_body"`
	ResponseBody           bool               `json:"response_body,omitempty"`
	ExecutingParanoiaLevel int                `json:"executing_paranoia_level,omitempty"`
	OutboundScore          int                `json:"outbound_score,omitempty"`
	EarlyBlocking          bool               `json:"early_blocking,omitempty"`
	SamplingPercentage     int                `json:"sampling_percentage,omitempty"`
	ExcludedPaths          string             `json:"excluded_paths"`
	ExcludedIPs            string             `json:"excluded_ips"`
	CustomRules            string             `json:"custom_rules"`
	GuidedRules            []guidedPolicyRule `json:"guided_rules"`
	Exclusions             []PolicyExclusion  `json:"exclusions,omitempty"`
	CustomRuleObjects      []PolicyCustomRule `json:"custom_rule_objects,omitempty"`
}

func (s *Server) apiValidatePolicy(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		writeProblem(w, http.StatusForbidden, "invalid csrf token")
		return
	}
	var request policyValidationRequest
	if err := decodeJSON(w, r, &request, 128<<10); err != nil {
		return
	}
	if request.ConfigSchemaVersion == PolicyConfigStorageStructured && (request.ExcludedPaths != "" || request.ExcludedIPs != "" || request.CustomRules != "" || len(request.GuidedRules) != 0) {
		writeProblem(w, http.StatusBadRequest, "structured config and legacy policy fields cannot be combined")
		return
	}
	request.Name = truncate(strings.TrimSpace(request.Name), 255)
	request.Description = truncate(strings.TrimSpace(request.Description), 1024)
	request.Target = strings.TrimSpace(request.Target)
	request.ExpectedRevision = strings.TrimSpace(request.ExpectedRevision)
	fieldErrors := make(map[string]string)
	if request.Name == "" {
		fieldErrors["name"] = "정책 이름을 입력하세요."
	}
	if request.ExecutingParanoiaLevel == 0 {
		request.ExecutingParanoiaLevel = request.ParanoiaLevel
	}
	if request.ExecutingParanoiaLevel < request.ParanoiaLevel || request.ExecutingParanoiaLevel > 4 {
		fieldErrors["executing_paranoia_level"] = "Executing PL은 Blocking PL 이상 4 이하여야 합니다."
	}
	if request.OutboundScore == 0 {
		request.OutboundScore = 4
	}
	if request.OutboundScore < 1 || request.OutboundScore > 100 {
		fieldErrors["outbound_score"] = "Outbound 임계점수는 1..100이어야 합니다."
	}
	if request.SamplingPercentage == 0 {
		request.SamplingPercentage = 100
	}
	if request.SamplingPercentage < 1 || request.SamplingPercentage > 100 {
		fieldErrors["sampling_percentage"] = "Sampling 비율은 1..100이어야 합니다."
	}
	customRules, err := mergeGuidedPolicyRules(request.CustomRules, request.GuidedRules)
	if err != nil {
		fieldErrors["guided_rules"] = err.Error()
	}

	session := sessionFrom(r)
	var policy *EnterprisePolicyRecord
	var policyTemplate systempolicy.Template
	if request.PolicyID != "" {
		loaded, loadErr := s.store.EnterprisePolicyByID(r.Context(), session.ScopeEnterpriseID(), truncate(strings.TrimSpace(request.PolicyID), 64))
		if loadErr != nil {
			writeProblem(w, http.StatusNotFound, "policy not found")
			return
		}
		policy = &loaded
		request.Target = loaded.Target
		if request.ExpectedRevision == "" || request.ExpectedRevision != loaded.CurrentRevisionID {
			fieldErrors["expected_revision_id"] = "다른 관리자가 먼저 정책을 변경했습니다. 최신 상태를 다시 확인하세요."
		}
		var found bool
		policyTemplate, found = s.systemPolicyTemplate(r.Context(), loaded.CurrentSystemPolicyID)
		if !found {
			fieldErrors["template_key"] = "현재 CRS 기반 시스템 정책을 확인할 수 없습니다."
		}
	} else {
		if request.Target == "" {
			fieldErrors["target"] = "배포 대상을 선택하세요."
		}
		var found bool
		policyTemplate, found = s.latestSystemPolicyTemplate(r.Context(), strings.TrimSpace(request.TemplateKey))
		if !found {
			fieldErrors["template_key"] = "지원하는 시스템 정책을 선택하세요."
		}
	}

	metadata := ManagedPolicyMetadata{
		SchemaVersion: policyTemplate.SchemaVersion, TemplateKey: policyTemplate.Key, TemplateVersion: policyTemplate.Version,
		CRSTrack: policyTemplate.CRSTrack, CRSVersion: policyTemplate.CRSVersion, Target: request.Target,
		PolicyOrigin: "administrator", MigrationStatus: "CURRENT",
	}
	if request.ConfigSchemaVersion == PolicyConfigStorageStructured {
		configuration := PolicyConfiguration{
			PolicyRevisionID: "validation", EngineMode: request.Mode, BlockingParanoiaLevel: request.ParanoiaLevel,
			ExecutingParanoiaLevel: request.ExecutingParanoiaLevel, InboundAnomalyThreshold: request.InboundScore,
			OutboundAnomalyThreshold: request.OutboundScore, RequestBodyAccess: request.RequestBody, ResponseBodyAccess: request.ResponseBody,
			EarlyBlocking: request.EarlyBlocking, SamplingPercentage: request.SamplingPercentage, RuleIDNamespaceVersion: 1,
			Exclusions: request.Exclusions, CustomRules: request.CustomRuleObjects,
		}
		if policyTemplate.Defaults.CRSSource != nil {
			configuration.CRSReleaseID = policyTemplate.Defaults.CRSSource.ID
		}
		if err := configuration.UpdateDigest(); err != nil {
			fieldErrors["configuration"] = err.Error()
		} else if err := configuration.ValidateAt(time.Now().UTC()); err != nil {
			fieldErrors["configuration"] = err.Error()
		} else if _, index, ok, indexErr := s.indexedPolicySource(r.Context(), configuration.CRSReleaseID); indexErr != nil {
			fieldErrors["configuration"] = "CRS DB 인덱스를 불러올 수 없습니다."
		} else if !ok {
			fieldErrors["configuration"] = "검증된 CRS 인덱스를 찾을 수 없습니다."
		} else if err := validateConfigurationRuleIDs(configuration, index); err != nil {
			fieldErrors["configuration"] = err.Error()
		}
		if len(fieldErrors) != 0 {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"valid": false, "field_errors": fieldErrors})
			return
		}
		enterpriseID, serverIDs, targetErr := s.store.ResolvePolicyTarget(r.Context(), session.ScopeEnterpriseID(), request.Target)
		if targetErr != nil || len(serverIDs) == 0 {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"valid": false, "field_errors": map[string]string{"target": "현재 우선순위에서 실제 적용되는 서버가 없습니다."}})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"valid": true, "normalized": map[string]any{"name": request.Name, "description": request.Description, "configuration": configuration}, "impact": map[string]any{"enterprise_id": enterpriseID, "server_ids": serverIDs, "server_count": len(serverIDs)}})
		return
	}
	_, settingsJSON, buildErr := buildEnterprisePolicyArtifact(policyTemplate, request.Mode, request.ParanoiaLevel, request.InboundScore, request.RequestBody, request.ExcludedPaths, request.ExcludedIPs, customRules, metadata)
	if buildErr != nil {
		fieldErrors[policyErrorField(buildErr)] = buildErr.Error()
	}
	if len(fieldErrors) != 0 {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"valid": false, "field_errors": fieldErrors})
		return
	}

	enterpriseID, serverIDs, targetErr := s.store.ResolvePolicyTarget(r.Context(), session.ScopeEnterpriseID(), request.Target)
	if targetErr != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"valid": false, "field_errors": map[string]string{"target": "정책 대상을 찾을 수 없습니다."}})
		return
	}
	if policy != nil {
		enterpriseID = policy.EnterpriseID
		serverIDs, targetErr = s.policyWinnerServerIDs(r, *policy)
	}
	if targetErr != nil || len(serverIDs) == 0 {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"valid": false, "field_errors": map[string]string{"target": "현재 우선순위에서 실제 적용되는 서버가 없습니다."}})
		return
	}
	var settings PolicySettings
	_ = json.Unmarshal([]byte(settingsJSON), &settings)
	settings.ExecutingParanoiaLevel = request.ExecutingParanoiaLevel
	settings.OutboundScore = request.OutboundScore
	settings.ResponseBody = request.ResponseBody
	settings.EarlyBlocking = request.EarlyBlocking
	settings.SamplingPercentage = request.SamplingPercentage
	writeJSON(w, http.StatusOK, map[string]any{"valid": true, "normalized": map[string]any{"name": request.Name, "description": request.Description, "mode": request.Mode, "settings": settings}, "impact": map[string]any{"enterprise_id": enterpriseID, "server_ids": serverIDs, "server_count": len(serverIDs)}})
}

func policyErrorField(err error) string {
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "path"):
		return "excluded_paths"
	case strings.Contains(message, "ip") || strings.Contains(message, "cidr"):
		return "excluded_ips"
	case strings.Contains(message, "rule") || strings.Contains(message, "action") || strings.Contains(message, "operator"):
		return "custom_rules"
	case strings.Contains(message, "mode"):
		return "mode"
	case strings.Contains(message, "paranoia"):
		return "paranoia_level"
	case strings.Contains(message, "score"):
		return "inbound_score"
	default:
		return "policy"
	}
}

func mergeGuidedPolicyRules(advanced string, rules []guidedPolicyRule) (string, error) {
	lines := make([]string, 0, len(rules)+1)
	usedIDs := make(map[int]bool)
	for _, match := range customRuleID.FindAllStringSubmatch(advanced, -1) {
		if len(match) != 2 {
			continue
		}
		id, _ := strconv.Atoi(match[1])
		usedIDs[id] = true
	}
	nextID := enterpriseRuleIDMin
	for index, rule := range rules {
		field := strings.TrimSpace(rule.Field)
		switch field {
		case "REQUEST_URI", "REQUEST_METHOD", "REQUEST_HEADERS:Host", "REQUEST_HEADERS:User-Agent", "ARGS":
		default:
			return "", fmt.Errorf("안내형 규칙 %d의 요청 필드가 올바르지 않습니다.", index+1)
		}
		if field == "ARGS" {
			argument := strings.TrimSpace(rule.Argument)
			if !validGuidedArgumentName(argument) {
				return "", fmt.Errorf("안내형 규칙 %d의 요청 인자 이름이 올바르지 않습니다.", index+1)
			}
			field += ":" + argument
		}
		operator := strings.TrimSpace(rule.Operator)
		switch operator {
		case "@contains", "@beginsWith", "@streq":
		default:
			return "", fmt.Errorf("안내형 규칙 %d의 연산자가 올바르지 않습니다.", index+1)
		}
		value := strings.TrimSpace(rule.Value)
		if value == "" || len(value) > 512 || strings.ContainsAny(value, "\"\\\r\n") {
			return "", fmt.Errorf("안내형 규칙 %d의 값에 따옴표, 역슬래시 또는 줄바꿈을 사용할 수 없습니다.", index+1)
		}
		actions := "pass,log"
		switch strings.TrimSpace(rule.Action) {
		case "block":
			actions = "deny,status:403,log"
		case "detect":
		case "":
			return "", fmt.Errorf("안내형 규칙 %d의 동작을 선택하세요.", index+1)
		default:
			return "", fmt.Errorf("안내형 규칙 %d의 동작이 올바르지 않습니다.", index+1)
		}
		for usedIDs[nextID] && nextID <= enterpriseRuleIDMax {
			nextID++
		}
		if nextID > enterpriseRuleIDMax {
			return "", errors.New("안내형 규칙에 사용할 수 있는 Rule ID가 없습니다")
		}
		lines = append(lines, fmt.Sprintf(`SecRule %s "%s %s" "id:%d,phase:1,%s,msg:M-WAF guided rule %d"`, field, operator, value, nextID, actions, index+1))
		usedIDs[nextID] = true
		nextID++
	}
	advanced = strings.TrimSpace(advanced)
	if advanced != "" {
		lines = append(lines, advanced)
	}
	return strings.Join(lines, "\n"), nil
}

func splitGuidedPolicyRules(customRules string) (string, []guidedPolicyRule) {
	advanced := make([]string, 0)
	guided := make([]guidedPolicyRule, 0)
	for _, line := range strings.Split(strings.ReplaceAll(customRules, "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		match := guidedPolicyRuleLine.FindStringSubmatch(trimmed)
		if len(match) != 6 {
			if trimmed != "" {
				advanced = append(advanced, trimmed)
			}
			continue
		}
		field, argument := match[1], ""
		if strings.HasPrefix(field, "ARGS:") {
			field, argument = "ARGS", strings.TrimPrefix(field, "ARGS:")
		}
		action := "detect"
		if match[5] == "deny,status:403,log" {
			action = "block"
		}
		rule := guidedPolicyRule{Field: field, Argument: argument, Operator: match[2], Value: match[3], Action: action}
		if _, err := mergeGuidedPolicyRules("", []guidedPolicyRule{rule}); err != nil {
			advanced = append(advanced, trimmed)
			continue
		}
		guided = append(guided, rule)
	}
	return strings.Join(advanced, "\n"), guided
}

func validGuidedArgumentName(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '_' || character == '-' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func guidedRulesFromForm(r *http.Request) ([]guidedPolicyRule, error) {
	raw := strings.TrimSpace(r.FormValue("guided_rules_json"))
	if raw == "" {
		return nil, nil
	}
	var rules []guidedPolicyRule
	if err := json.Unmarshal([]byte(raw), &rules); err != nil {
		return nil, errors.New("안내형 규칙 입력을 읽을 수 없습니다")
	}
	if len(rules) > 100 {
		return nil, errors.New("안내형 규칙은 100개까지 입력할 수 있습니다")
	}
	return rules, nil
}

func enterprisePolicyExclusionsFromForm(r *http.Request) ([]PolicyExclusion, error) {
	after, err := parseRuleExclusions(r.FormValue("rule_exclusions"))
	if err != nil {
		return nil, err
	}
	targets, err := parseTargetExclusions(r.FormValue("target_exclusions"))
	if err != nil {
		return nil, err
	}
	before, conditionalTargets, err := parseConditionalExclusions(r.FormValue("conditional_exclusions"))
	if err != nil {
		return nil, err
	}
	var result []PolicyExclusion
	appendConditions := func(conditions []systempolicy.RuleCondition) []PolicyExclusionCondition {
		items := make([]PolicyExclusionCondition, 0, len(conditions))
		for index, condition := range conditions {
			items = append(items, PolicyExclusionCondition{Field: condition.Field, Operator: condition.Operator, Value: condition.Value, Order: index})
		}
		return items
	}
	for _, item := range after {
		result = append(result, PolicyExclusion{SourceScope: PolicyScopeEnterprise, Type: PolicyExclusionRule, LoadStage: PolicyExclusionAfter, RuleID: item.RuleID, Enabled: true})
	}
	for _, item := range before {
		result = append(result, PolicyExclusion{SourceScope: PolicyScopeEnterprise, Type: PolicyExclusionRule, LoadStage: PolicyExclusionBefore, RuleID: item.RuleID, Enabled: true, Conditions: appendConditions(item.Conditions)})
	}
	for _, item := range append(targets, conditionalTargets...) {
		stage := PolicyExclusionAfter
		if len(item.Conditions) != 0 {
			stage = PolicyExclusionBefore
		}
		result = append(result, PolicyExclusion{SourceScope: PolicyScopeEnterprise, Type: PolicyExclusionTarget, LoadStage: stage, RuleID: item.RuleID, Target: item.Target, Enabled: true, Conditions: appendConditions(item.Conditions)})
	}
	for _, tag := range uniqueNonEmptyLines(r.FormValue("tag_exclusions")) {
		if len(tag) > 255 || strings.ContainsAny(tag, "\"'\r\n") {
			return nil, errors.New("Rule tag 예외가 올바르지 않습니다")
		}
		result = append(result, PolicyExclusion{SourceScope: PolicyScopeEnterprise, Type: PolicyExclusionTag, LoadStage: PolicyExclusionAfter, RuleTag: tag, Enabled: true})
	}
	bypassValue := strings.TrimSpace(r.FormValue("bypass_value"))
	bypassReason := strings.TrimSpace(r.FormValue("bypass_reason"))
	if bypassValue != "" || bypassReason != "" {
		expiresAt, err := localtime.ParseKST("2006-01-02T15:04", strings.TrimSpace(r.FormValue("bypass_expires_at")))
		if err != nil {
			return nil, errors.New("긴급 전체 우회의 만료 시각을 입력하세요")
		}
		field := strings.TrimSpace(r.FormValue("bypass_field"))
		operator := strings.TrimSpace(r.FormValue("bypass_operator"))
		if bypassReason == "" || !validConditionField(field) || !validConditionOperator(operator) {
			return nil, errors.New("긴급 전체 우회의 사유와 안전한 조건을 입력하세요")
		}
		expiresAt = expiresAt.UTC()
		result = append(result, PolicyExclusion{
			SourceScope: PolicyScopeEnterprise, Type: PolicyExclusionEngineBypass, LoadStage: PolicyExclusionBefore,
			Reason: bypassReason, ExpiresAt: &expiresAt, Enabled: true,
			Conditions: []PolicyExclusionCondition{{Field: field, Operator: operator, Value: bypassValue}},
		})
	}
	for index := range result {
		result[index].Order = index
	}
	return result, nil
}

func enterpriseExclusionFormValues(items []PolicyExclusion) (rules, tags, targets, conditional string) {
	var ruleLines, tagLines, targetLines, conditionalLines []string
	for _, item := range items {
		switch {
		case item.LoadStage == PolicyExclusionAfter && item.Type == PolicyExclusionRule:
			ruleLines = append(ruleLines, strconv.Itoa(item.RuleID))
		case item.LoadStage == PolicyExclusionAfter && item.Type == PolicyExclusionTag:
			tagLines = append(tagLines, item.RuleTag)
		case item.LoadStage == PolicyExclusionAfter && item.Type == PolicyExclusionTarget:
			targetLines = append(targetLines, fmt.Sprintf("%d|%s", item.RuleID, item.Target))
		case item.LoadStage == PolicyExclusionBefore && len(item.Conditions) != 0:
			for _, condition := range item.Conditions {
				target := ""
				if item.Type == PolicyExclusionTarget {
					target = item.Target
				}
				conditionalLines = append(conditionalLines, fmt.Sprintf("%d|%s|%s|%s|%s", item.RuleID, target, condition.Field, condition.Operator, condition.Value))
			}
		}
	}
	return strings.Join(ruleLines, "\n"), strings.Join(tagLines, "\n"), strings.Join(targetLines, "\n"), strings.Join(conditionalLines, "\n")
}

func (s *Server) editEnterprisePolicy(w http.ResponseWriter, r *http.Request) {
	policy, err := s.store.EnterprisePolicyByID(r.Context(), sessionFrom(r).ScopeEnterpriseID(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.renderAdminError(w, r, http.StatusNotFound, "기업 정책을 찾을 수 없습니다", "현재 기업 범위에서 접근할 수 없는 정책입니다.")
			return
		}
		s.renderAdminError(w, r, http.StatusInternalServerError, "기업 정책을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	if policy.Status != EnterprisePolicyActive || policy.CurrentSystemPolicyID == "" {
		s.renderAdminError(w, r, http.StatusConflict, "이 정책은 편집할 수 없습니다", "시스템 정책 기반으로 전환한 뒤 새 개정본을 만들 수 있습니다.")
		return
	}
	settings := policy.CurrentSettings
	ruleExclusions, tagExclusions, targetExclusions, conditionalExclusions := enterpriseExclusionFormValues(settings.Exclusions)
	existingEngineBypasses := 0
	for _, exclusion := range settings.Exclusions {
		if exclusion.Type == PolicyExclusionEngineBypass && !exclusion.Legacy {
			existingEngineBypasses++
		}
	}
	advancedRules, guidedRules := splitGuidedPolicyRules(settings.CustomRules)
	guidedRulesJSON, _ := json.Marshal(guidedRules)
	paths := append([]string(nil), settings.ExcludedPaths...)
	if exceptionURI := strings.TrimSpace(r.URL.Query().Get("exception_uri")); exceptionURI != "" && strings.HasPrefix(exceptionURI, "/") {
		found := false
		for _, path := range paths {
			if path == exceptionURI {
				found = true
			}
		}
		if !found {
			paths = append(paths, exceptionURI)
		}
	}
	form := map[string]any{
		"IsEdit": true, "EditPolicy": policy, "FormEnterpriseID": policy.EnterpriseID, "FormExpectedRevision": policy.CurrentRevisionID,
		"FormTemplateKey": settings.TemplateKey, "FormName": policy.Name, "FormDescription": policy.Description, "FormTarget": policy.Target,
		"FormStrategy": policy.UpdateStrategy, "FormMode": policy.CurrentMode, "FormParanoia": strconv.Itoa(settings.ParanoiaLevel),
		"FormExecutingParanoia": strconv.Itoa(settings.ExecutingParanoiaLevel), "FormScore": strconv.Itoa(settings.InboundScore),
		"FormOutboundScore": strconv.Itoa(settings.OutboundScore), "FormRequestBody": settings.RequestBody, "FormResponseBody": settings.ResponseBody,
		"FormEarlyBlocking": settings.EarlyBlocking, "FormSamplingPercentage": strconv.Itoa(settings.SamplingPercentage),
		"FormExcludedPaths": strings.Join(paths, "\n"), "FormExcludedIPs": strings.Join(settings.ExcludedIPs, "\n"), "FormCustomRules": advancedRules, "FormGuidedRules": string(guidedRulesJSON),
		"FormRuleExclusions": ruleExclusions, "FormTagExclusions": tagExclusions, "FormTargetExclusions": targetExclusions, "FormConditionalExclusions": conditionalExclusions,
		"ExistingEngineBypasses": existingEngineBypasses,
		"HasAdvancedSettings":    settings.ParanoiaLevel != 1 || settings.ExecutingParanoiaLevel != 1 || settings.InboundScore != 5 || settings.OutboundScore != 4 || !settings.RequestBody || settings.ResponseBody || settings.EarlyBlocking || settings.SamplingPercentage != 100 || len(settings.Exclusions) != 0 || strings.TrimSpace(advancedRules) != "" || len(settings.ExcludedPaths) != 0 || len(settings.ExcludedIPs) != 0,
	}
	s.renderPolicyForm(w, r, http.StatusOK, "", form)
}

func (s *Server) createEnterprisePolicyRevision(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		s.renderAdminError(w, r, http.StatusForbidden, "보안 정보가 만료되었습니다", "화면을 새로고침한 뒤 다시 시도하세요.")
		return
	}
	policy, err := s.store.EnterprisePolicyByID(r.Context(), sessionFrom(r).ScopeEnterpriseID(), r.PathValue("id"))
	if err != nil {
		s.writePolicyMutationError(w, r, r.PathValue("id"), err)
		return
	}
	expectedRevisionID := strings.TrimSpace(r.FormValue("expected_revision_id"))
	form := policyFormState(r)
	form["IsEdit"], form["EditPolicy"], form["FormEnterpriseID"], form["FormExpectedRevision"] = true, policy, policy.EnterpriseID, expectedRevisionID
	if r.FormValue("publish_confirm") != "confirmed" {
		s.renderPolicyForm(w, r, http.StatusBadRequest, "변경 내용과 단계 배포 영향을 확인해야 합니다.", form)
		return
	}
	if expectedRevisionID == "" || expectedRevisionID != policy.CurrentRevisionID {
		s.renderPolicyForm(w, r, http.StatusConflict, "다른 관리자가 먼저 정책을 변경했습니다. 최신 개정본을 다시 확인하세요.", form)
		return
	}
	policyTemplate, ok := s.systemPolicyTemplate(r.Context(), policy.CurrentSystemPolicyID)
	if !ok || policyTemplate.Status == systempolicy.StatusWithdrawn {
		s.renderPolicyForm(w, r, http.StatusConflict, "현재 CRS 기반 시스템 정책으로 새 기업 정책 개정본을 만들 수 없습니다.", form)
		return
	}
	name := truncate(strings.TrimSpace(r.FormValue("name")), 255)
	description := truncate(strings.TrimSpace(r.FormValue("description")), 1024)
	mode := strings.TrimSpace(r.FormValue("mode"))
	paranoiaLevel, paranoiaErr := strconv.Atoi(strings.TrimSpace(r.FormValue("paranoia_level")))
	executingParanoiaLevel, executingErr := strconv.Atoi(strings.TrimSpace(r.FormValue("executing_paranoia_level")))
	inboundScore, scoreErr := strconv.Atoi(strings.TrimSpace(r.FormValue("inbound_score")))
	outboundScore, outboundErr := strconv.Atoi(strings.TrimSpace(r.FormValue("outbound_score")))
	samplingPercentage, samplingErr := strconv.Atoi(strings.TrimSpace(r.FormValue("sampling_percentage")))
	guided, guidedErr := guidedRulesFromForm(r)
	customRules, mergeErr := mergeGuidedPolicyRules(r.FormValue("custom_rules"), guided)
	exclusions, exclusionErr := enterprisePolicyExclusionsFromForm(r)
	if name == "" || paranoiaErr != nil || executingErr != nil || scoreErr != nil || outboundErr != nil || samplingErr != nil || guidedErr != nil || mergeErr != nil || exclusionErr != nil {
		message := "정책 이름과 세부 설정을 확인하세요."
		if guidedErr != nil {
			message = guidedErr.Error()
		} else if mergeErr != nil {
			message = mergeErr.Error()
		} else if exclusionErr != nil {
			message = exclusionErr.Error()
		}
		s.renderPolicyForm(w, r, http.StatusBadRequest, message, form)
		return
	}
	settings := policy.CurrentSettings
	if r.FormValue("remove_existing_engine_bypasses") != "confirmed" {
		for _, exclusion := range settings.Exclusions {
			if exclusion.Type == PolicyExclusionEngineBypass && !exclusion.Legacy {
				exclusions = append(exclusions, exclusion)
			}
		}
	}
	settings.ParanoiaLevel = paranoiaLevel
	settings.ExecutingParanoiaLevel = executingParanoiaLevel
	settings.InboundScore = inboundScore
	settings.OutboundScore = outboundScore
	settings.RequestBody = r.FormValue("request_body") == "on"
	settings.ResponseBody = r.FormValue("response_body") == "on"
	settings.EarlyBlocking = r.FormValue("early_blocking") == "on"
	settings.SamplingPercentage = samplingPercentage
	settings.LegacyPolicyConfirmed = r.FormValue("confirm_legacy_policy") == "confirmed"
	settings.ExcludedPaths = uniqueNonEmptyLines(r.FormValue("excluded_paths"))
	settings.ExcludedIPs = uniqueNonEmptyLines(r.FormValue("excluded_ips"))
	if r.FormValue("remove_legacy_bypass") == "confirmed" {
		settings.ExcludedPaths = nil
		settings.ExcludedIPs = nil
	}
	settings.Exclusions = exclusions
	settings.CustomRules = customRules
	settings.CustomRuleCount = 0
	settings.Target = policy.Target
	settings.PolicyOrigin = "administrator"
	settings.MigrationStatus = "CURRENT"
	origin := "administrator"
	if r.FormValue("confirm_legacy_policy") == "confirmed" {
		origin = "administrator-legacy-confirmed"
	}
	revision, fullPath, err := s.preparePolicyRevision(policyTemplate, name, description, mode, settings, policy.CurrentRevisionID, origin)
	if err != nil {
		s.renderPolicyForm(w, r, http.StatusBadRequest, "정책 설정이 올바르지 않습니다: "+err.Error(), form)
		return
	}
	serverIDs, err := s.policyWinnerServerIDs(r, policy)
	if err != nil || len(serverIDs) == 0 {
		_ = os.Remove(fullPath)
		s.renderPolicyForm(w, r, http.StatusConflict, "현재 우선순위에서 이 정책이 실제 적용되는 서버가 없습니다.", form)
		return
	}
	session := sessionFrom(r)
	rolloutID, err := s.store.CreatePolicyRollout(r.Context(), policy, expectedRevisionID, "UPDATE", "QUEUED", session.UserID, &revision, "", revision.SystemPolicyVersionID, serverIDs)
	if err != nil {
		_ = os.Remove(fullPath)
		if strings.Contains(err.Error(), "revision changed") || strings.Contains(err.Error(), "active rollout") {
			s.renderPolicyForm(w, r, http.StatusConflict, "정책 개정본 또는 단계 배포 상태가 변경되었습니다. 최신 상태를 다시 확인하세요.", form)
			return
		}
		s.renderPolicyForm(w, r, http.StatusInternalServerError, "새 정책 개정본을 배포할 수 없습니다. 잠시 후 다시 시도하세요.", form)
		return
	}
	s.audit(r, session.Username, "enterprise_policy.revision_create", policy.ID+":"+rolloutID, "success")
	s.TriggerPolicySync()
	s.redirectEnterprisePolicy(w, r, policy.ID, "새 불변 개정본의 단계 배포를 시작했습니다.")
}

func (s *Server) policyWinnerServerIDs(r *http.Request, policy EnterprisePolicyRecord) ([]string, error) {
	servers, err := s.store.ListServers(r.Context(), policy.EnterpriseID, systemPolicyServerLimit)
	if err != nil {
		return nil, err
	}
	policies, err := s.store.ListEnterprisePolicies(r.Context(), policy.EnterpriseID, systemPolicyServerLimit)
	if err != nil {
		return nil, err
	}
	candidate := policy
	candidate.CurrentRevisionID = "candidate"
	candidate.UpdatedAt = time.Now().UTC()
	found := false
	for index := range policies {
		if policies[index].ID == policy.ID {
			policies[index] = candidate
			found = true
			break
		}
	}
	if !found {
		policies = append(policies, candidate)
	}
	winners, err := s.enterprisePolicyWinners(r.Context(), policies, servers)
	if err != nil {
		return nil, err
	}
	return orderIDsByServers(winners[policy.ID], servers), nil
}
