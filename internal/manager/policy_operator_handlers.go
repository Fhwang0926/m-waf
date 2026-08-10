package manager

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Fhwang0926/m-waf/internal/localtime"
)

type policyIPRuleView struct {
	Policy EnterprisePolicyRecord
	Rule   PolicyIPRule
}

type policyScopedExceptionView struct {
	Policy    EnterprisePolicyRecord
	Exception policyExceptionView
}

type policyUserRuleView struct {
	Policy         EnterprisePolicyRecord
	Rule           PolicyCustomRule
	NameLabel      string
	TargetLabel    string
	ConditionLabel string
	ActionLabel    string
	ActionClass    string
	Guided         bool
}

type userPolicySummary struct {
	PolicyCount     int
	ExceptionCount  int
	IPRuleCount     int
	CustomRuleCount int
}

type policyExceptionView struct {
	Exclusion      PolicyExclusion
	ScopeLabel     string
	ConditionLabel string
	IncidentID     string
	Reason         string
	StatusLabel    string
	StatusClass    string
	ExpiresLabel   string
}

type incidentExceptionValidation struct {
	Policy              EnterprisePolicyRecord
	Incident            IncidentRecord
	Configuration       PolicyConfiguration
	Exclusion           PolicyExclusion
	Scope               string
	AffectedServerCount int
}

type incidentExceptionError struct {
	Status  int
	Message string
}

func (e *incidentExceptionError) Error() string { return e.Message }

func (v policyIPRuleView) ActionLabel() string {
	if v.Rule.Action == PolicyIPActionTrust {
		return "신뢰·검사 제외"
	}
	return "차단"
}

func (v policyIPRuleView) StatusLabel(now time.Time) string {
	if !v.Rule.Enabled {
		return "비활성"
	}
	if v.Rule.ExpiresAt != nil && !v.Rule.ExpiresAt.After(now) {
		return "만료 제거 대기"
	}
	return "적용 중"
}

func policyUserRuleViewFor(policy EnterprisePolicyRecord, rule PolicyCustomRule) policyUserRuleView {
	view := policyUserRuleView{
		Policy: policy, Rule: rule, NameLabel: strings.TrimSpace(rule.Name),
		TargetLabel: "고급 SecRule", ConditionLabel: "원문 규칙 확인", ActionLabel: "고급", ActionClass: "info",
	}
	if view.NameLabel == "" {
		view.NameLabel = "사용자 Rule " + strconv.Itoa(rule.RuleID)
	}
	advanced, guided := splitGuidedPolicyRules(rule.CanonicalSecRule)
	if advanced != "" || len(guided) != 1 {
		return view
	}
	item := guided[0]
	view.Guided = true
	view.TargetLabel = map[string]string{
		"REQUEST_URI": "요청 URL", "REQUEST_METHOD": "HTTP 메서드", "REQUEST_HEADERS:Host": "Host",
		"REQUEST_HEADERS:User-Agent": "User-Agent", "ARGS": "요청 인자 " + item.Argument,
	}[item.Field]
	view.ConditionLabel = map[string]string{"@streq": "일치", "@beginsWith": "시작", "@contains": "포함"}[item.Operator] + " · " + item.Value
	if item.Action == "block" {
		view.ActionLabel, view.ActionClass = "차단", "danger"
	} else {
		view.ActionLabel, view.ActionClass = "탐지", "warn"
	}
	return view
}

func userPolicySearchMatch(query string, values ...string) bool {
	if query == "" {
		return true
	}
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), query) {
			return true
		}
	}
	return false
}

func (s *Server) userPolicies(w http.ResponseWriter, r *http.Request) {
	requestedEnterprise := r.URL.Query().Get("enterprise_id")
	enterpriseID, ok := s.effectiveEnterpriseFilter(r, requestedEnterprise)
	if !ok {
		s.renderAdminError(w, r, http.StatusBadRequest, "기업 범위를 확인할 수 없습니다", "유효한 기업을 선택하세요.")
		return
	}
	policies, err := s.store.ListEnterprisePolicies(r.Context(), enterpriseID, 5000)
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "사용자 정책을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	filterPolicyID := truncate(strings.TrimSpace(r.URL.Query().Get("policy_id")), 64)
	filterType := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("type")))
	if filterType != "exception" && filterType != "ip" && filterType != "rule" {
		filterType = "all"
	}
	filterQuery := truncate(strings.TrimSpace(r.URL.Query().Get("q")), 255)
	query := strings.ToLower(filterQuery)
	policyOptions := make([]EnterprisePolicyRecord, 0, len(policies))
	activePolicies := make([]EnterprisePolicyRecord, 0, len(policies))
	exceptions := make([]policyScopedExceptionView, 0)
	ipRules := make([]policyIPRuleView, 0)
	customRules := make([]policyUserRuleView, 0)
	summary := userPolicySummary{}
	now := time.Now().UTC()
	for _, policy := range policies {
		if policy.Status != EnterprisePolicyActive || policy.CurrentRevisionID == "" {
			continue
		}
		configuration, configurationErr := currentPolicyConfiguration(r.Context(), s.store, policy)
		if configurationErr != nil {
			continue
		}
		policy.CurrentConfiguration = &configuration
		policyOptions = append(policyOptions, policy)
		if filterPolicyID != "" && policy.ID != filterPolicyID {
			continue
		}
		activePolicies = append(activePolicies, policy)
		summary.PolicyCount++
		for _, item := range policyExceptionViews(&configuration, now) {
			summary.ExceptionCount++
			if (filterType == "all" || filterType == "exception") && userPolicySearchMatch(query, policy.Name, item.ScopeLabel, item.ConditionLabel, item.Reason, strconv.Itoa(item.Exclusion.RuleID), item.Exclusion.Target) {
				exceptions = append(exceptions, policyScopedExceptionView{Policy: policy, Exception: item})
			}
		}
		for _, rule := range configuration.IPRules {
			if rule.SourceScope == PolicyScopeEnterprise {
				summary.IPRuleCount++
				view := policyIPRuleView{Policy: policy, Rule: rule}
				if (filterType == "all" || filterType == "ip") && userPolicySearchMatch(query, policy.Name, rule.Network, rule.Reason, view.ActionLabel()) {
					ipRules = append(ipRules, view)
				}
			}
		}
		for _, rule := range configuration.CustomRules {
			if rule.SourceScope != PolicyScopeEnterprise {
				continue
			}
			summary.CustomRuleCount++
			view := policyUserRuleViewFor(policy, rule)
			if (filterType == "all" || filterType == "rule") && userPolicySearchMatch(query, policy.Name, view.NameLabel, view.TargetLabel, view.ConditionLabel, strconv.Itoa(rule.RuleID), rule.CanonicalSecRule) {
				customRules = append(customRules, view)
			}
		}
	}
	data := map[string]any{
		"Policies": activePolicies, "PolicyOptions": policyOptions, "PolicyExceptions": exceptions, "IPRules": ipRules, "CustomRules": customRules,
		"Summary": summary, "Now": now, "FilterEnterprise": enterpriseID,
		"FilterPolicyID": filterPolicyID, "FilterType": filterType, "FilterQuery": filterQuery,
		"Notice": r.URL.Query().Get("notice"),
	}
	_ = s.templates.ExecuteTemplate(w, "user-policies.html", s.viewData(r, "user-policies", data))
}

func (s *Server) legacyIPRulesRedirect(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	query.Set("type", "ip")
	http.Redirect(w, r, "/user-policies?"+query.Encode(), http.StatusSeeOther)
}

func exceptionRequestError(status int, message string) error {
	return &incidentExceptionError{Status: status, Message: message}
}

func incidentExceptionExpiry(scope, value string, role Role, now time.Time) (*time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		if scope == "global" {
			value = "24h"
		} else {
			value = "30d"
		}
	}
	if value == "permanent" {
		if scope == "global" {
			return nil, exceptionRequestError(http.StatusBadRequest, "전체 범위 예외는 최대 7일까지만 유지할 수 있습니다.")
		}
		if !roleAtLeast(role, RoleEnterpriseAdmin) {
			return nil, exceptionRequestError(http.StatusForbidden, "영구 예외는 기업 관리자만 만들 수 있습니다.")
		}
		return nil, nil
	}
	durations := map[string]time.Duration{
		"24h": 24 * time.Hour,
		"7d":  7 * 24 * time.Hour,
		"30d": 30 * 24 * time.Hour,
		"90d": 90 * 24 * time.Hour,
	}
	duration, ok := durations[value]
	if !ok || scope == "global" && duration > 7*24*time.Hour {
		return nil, exceptionRequestError(http.StatusBadRequest, "예외 만료 기간을 확인하세요.")
	}
	expiresAt := now.UTC().Add(duration)
	return &expiresAt, nil
}

func sameExceptionConditions(left, right []PolicyExclusionCondition) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].Field != right[index].Field || left[index].Operator != right[index].Operator || left[index].Value != right[index].Value {
			return false
		}
	}
	return true
}

func samePolicyException(left, right PolicyExclusion) bool {
	return left.Type == right.Type && left.LoadStage == right.LoadStage && left.RuleID == right.RuleID && left.RuleTag == right.RuleTag && left.Target == right.Target && sameExceptionConditions(left.Conditions, right.Conditions)
}

func exceptionURI(item PolicyExclusion) string {
	for _, condition := range item.Conditions {
		if condition.Field == "REQUEST_URI" && condition.Operator == "@streq" {
			return condition.Value
		}
	}
	return ""
}

func overlappingPolicyException(configuration PolicyConfiguration, candidate PolicyExclusion, now time.Time) string {
	candidateURI := exceptionURI(candidate)
	for _, existing := range configuration.Exclusions {
		if existing.SourceScope != PolicyScopeEnterprise || !existing.Enabled || existing.ExpiresAt != nil && !existing.ExpiresAt.After(now) || existing.RuleID != candidate.RuleID {
			continue
		}
		if samePolicyException(existing, candidate) {
			return "동일한 예외가 이미 현재 정책에 적용되어 있습니다."
		}
		if existing.Type == PolicyExclusionRule && existing.LoadStage == PolicyExclusionAfter && len(existing.Conditions) == 0 {
			return "이 Rule은 이미 모든 요청에서 제외되어 있습니다."
		}
		if candidateURI != "" && existing.Type == PolicyExclusionRule && existing.LoadStage == PolicyExclusionBefore && exceptionURI(existing) == candidateURI {
			return "이 URL에서는 이미 해당 Rule 전체가 제외되어 있습니다."
		}
	}
	return ""
}

func exceptionSourceReason(reason string) (incidentID, displayReason string) {
	const prefix = "보안 이벤트 "
	reason = strings.TrimSpace(reason)
	if !strings.HasPrefix(reason, prefix) {
		return "", reason
	}
	rest := strings.TrimPrefix(reason, prefix)
	end := 0
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	incidentID = rest[:end]
	displayReason = strings.TrimSpace(rest[end:])
	displayReason = strings.TrimSpace(strings.TrimPrefix(displayReason, "·"))
	if displayReason == "" {
		displayReason = "탐지 이벤트에서 생성"
	}
	return incidentID, displayReason
}

func policyExceptionViews(configuration *PolicyConfiguration, now time.Time) []policyExceptionView {
	if configuration == nil {
		return nil
	}
	items := make([]policyExceptionView, 0)
	for _, exclusion := range configuration.Exclusions {
		if exclusion.SourceScope != PolicyScopeEnterprise {
			continue
		}
		view := policyExceptionView{Exclusion: exclusion, StatusLabel: "적용 중", StatusClass: "ok", ExpiresLabel: "영구"}
		switch {
		case exclusion.Type == PolicyExclusionTarget && exclusion.LoadStage == PolicyExclusionBefore:
			view.ScopeLabel = "입력 항목"
			view.ConditionLabel = exceptionURI(exclusion) + " · " + exclusion.Target
		case exclusion.Type == PolicyExclusionRule && exclusion.LoadStage == PolicyExclusionBefore:
			view.ScopeLabel = "특정 URL"
			view.ConditionLabel = exceptionURI(exclusion)
		case exclusion.Type == PolicyExclusionRule && exclusion.LoadStage == PolicyExclusionAfter:
			view.ScopeLabel = "전체 요청"
			view.ConditionLabel = "모든 URL"
		default:
			view.ScopeLabel = "고급 예외"
			view.ConditionLabel = exclusion.Target
		}
		view.IncidentID, view.Reason = exceptionSourceReason(exclusion.Reason)
		if exclusion.ExpiresAt != nil {
			view.ExpiresLabel = exclusion.ExpiresAt.In(time.FixedZone("KST", 9*60*60)).Format("2006-01-02 15:04 KST")
			if !exclusion.ExpiresAt.After(now) {
				view.StatusLabel, view.StatusClass = "만료·제거 대기", "warn"
			}
		}
		if !exclusion.Enabled {
			view.StatusLabel, view.StatusClass = "비활성", "muted"
		}
		items = append(items, view)
	}
	return items
}

func (s *Server) validateIncidentException(ctx context.Context, session sessionData, policyID string, incidentID uint64, scope, reason, expiry string, now time.Time) (incidentExceptionValidation, error) {
	policy, err := s.store.EnterprisePolicyByID(ctx, session.ScopeEnterpriseID(), policyID)
	if err != nil {
		return incidentExceptionValidation{}, exceptionRequestError(http.StatusNotFound, "현재 기업에서 보호 정책을 찾을 수 없습니다.")
	}
	if policy.Status != EnterprisePolicyActive || policy.HasActiveRollout {
		return incidentExceptionValidation{}, exceptionRequestError(http.StatusConflict, "현재 정책 배포가 끝난 뒤 예외를 다시 검토하세요.")
	}
	incident, err := s.store.IncidentByID(ctx, session.ScopeEnterpriseID(), incidentID)
	if err != nil || incident.PolicyID != policy.ID || incident.PolicyRevision != policy.CurrentRevisionID {
		return incidentExceptionValidation{}, exceptionRequestError(http.StatusConflict, "이 이벤트는 현재 정책 개정본과 일치하지 않습니다. 최신 이벤트를 선택하세요.")
	}
	ruleID, err := strconv.Atoi(incident.PrimaryRuleID)
	if err != nil || ruleID <= 0 || isSummaryRule(incident.PrimaryRuleID) {
		return incidentExceptionValidation{}, exceptionRequestError(http.StatusConflict, "이 이벤트에는 예외 처리할 수 있는 원본 탐지 Rule이 없습니다.")
	}
	reason = truncate(strings.TrimSpace(reason), 512)
	if reason == "" {
		return incidentExceptionValidation{}, exceptionRequestError(http.StatusBadRequest, "예외가 필요한 운영 사유를 입력하세요.")
	}
	if scope == "global" && !roleAtLeast(session.Role, RoleEnterpriseAdmin) {
		return incidentExceptionValidation{}, exceptionRequestError(http.StatusForbidden, "전체 범위 예외는 기업 관리자만 만들 수 있습니다.")
	}
	expiresAt, err := incidentExceptionExpiry(scope, expiry, session.Role, now)
	if err != nil {
		return incidentExceptionValidation{}, err
	}
	configuration, err := currentPolicyConfiguration(ctx, s.store, policy)
	if err != nil {
		return incidentExceptionValidation{}, exceptionRequestError(http.StatusConflict, "현재 정책 설정을 불러올 수 없습니다.")
	}
	configuration.Exclusions = append([]PolicyExclusion(nil), configuration.Exclusions...)
	exclusion := PolicyExclusion{
		ID: randomID(), SourceScope: PolicyScopeEnterprise, RuleID: ruleID, Enabled: true,
		Reason: "보안 이벤트 " + strconv.FormatUint(incident.ID, 10) + " · " + reason, ExpiresAt: expiresAt, Order: len(configuration.Exclusions),
	}
	switch scope {
	case "input":
		if incident.MatchedVariable == "" {
			return incidentExceptionValidation{}, exceptionRequestError(http.StatusBadRequest, "탐지 입력 위치가 없어 입력 항목 예외를 만들 수 없습니다.")
		}
		exclusion.Type, exclusion.LoadStage, exclusion.Target = PolicyExclusionTarget, PolicyExclusionBefore, incident.MatchedVariable
		exclusion.Conditions = []PolicyExclusionCondition{{Field: "REQUEST_URI", Operator: "@streq", Value: incident.URI}}
	case "url":
		exclusion.Type, exclusion.LoadStage = PolicyExclusionRule, PolicyExclusionBefore
		exclusion.Conditions = []PolicyExclusionCondition{{Field: "REQUEST_URI", Operator: "@streq", Value: incident.URI}}
	case "global":
		exclusion.Type, exclusion.LoadStage = PolicyExclusionRule, PolicyExclusionAfter
	default:
		return incidentExceptionValidation{}, exceptionRequestError(http.StatusBadRequest, "입력 항목, 특정 URL 또는 전체 요청 중 예외 범위를 선택하세요.")
	}
	if overlap := overlappingPolicyException(configuration, exclusion, now); overlap != "" {
		return incidentExceptionValidation{}, exceptionRequestError(http.StatusConflict, overlap)
	}
	if exclusion.LoadStage == PolicyExclusionBefore {
		exclusion.GeneratedRuleID, err = nextGeneratedPolicyRuleID(configuration)
		if err != nil {
			return incidentExceptionValidation{}, exceptionRequestError(http.StatusConflict, err.Error())
		}
	}
	serverIDs, err := s.store.ListPolicyServerIDs(ctx, policy.EnterpriseID, policy.ID)
	if err != nil {
		return incidentExceptionValidation{}, exceptionRequestError(http.StatusInternalServerError, "예외가 적용될 서버를 확인할 수 없습니다.")
	}
	if len(serverIDs) == 0 {
		return incidentExceptionValidation{}, exceptionRequestError(http.StatusConflict, "이 보호 정책에 연결된 서버가 없어 예외를 배포할 수 없습니다.")
	}
	return incidentExceptionValidation{Policy: policy, Incident: incident, Configuration: configuration, Exclusion: exclusion, Scope: scope, AffectedServerCount: len(serverIDs)}, nil
}

func (s *Server) createIncidentException(w http.ResponseWriter, r *http.Request) {
	if !s.requirePolicyForm(w, r) {
		return
	}
	session := sessionFrom(r)
	policyID := r.PathValue("id")
	incidentID, err := strconv.ParseUint(strings.TrimSpace(r.FormValue("incident_id")), 10, 64)
	if err != nil || incidentID == 0 {
		s.renderAdminError(w, r, http.StatusBadRequest, "예외를 만들 수 없습니다", "유효한 보안 이벤트가 필요합니다.")
		return
	}
	if r.FormValue("publish_confirm") != "confirmed" {
		s.renderAdminError(w, r, http.StatusBadRequest, "예외 적용 확인이 필요합니다", "적용 범위와 영향 서버를 확인한 뒤 다시 시도하세요.")
		return
	}
	validation, err := s.validateIncidentException(r.Context(), session, policyID, incidentID, strings.TrimSpace(r.FormValue("scope")), r.FormValue("reason"), r.FormValue("expires_in"), time.Now().UTC())
	if err != nil {
		var requestErr *incidentExceptionError
		if errors.As(err, &requestErr) {
			s.renderAdminError(w, r, requestErr.Status, "예외를 적용할 수 없습니다", requestErr.Message)
			return
		}
		s.renderAdminError(w, r, http.StatusInternalServerError, "예외를 적용할 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	validation.Configuration.Exclusions = append(validation.Configuration.Exclusions, validation.Exclusion)
	rolloutID, err := s.createConfigurationRollout(r.Context(), validation.Policy, strings.TrimSpace(r.FormValue("expected_revision_id")), session.UserID, "incident-exception", validation.Configuration)
	if err != nil {
		s.writePolicyMutationError(w, r, policyID, err)
		return
	}
	s.audit(r, session.Username, "enterprise_policy.exception_create", policyID+":"+rolloutID+":"+strconv.FormatUint(validation.Incident.ID, 10)+":"+validation.Scope+":"+strconv.Itoa(validation.Exclusion.RuleID), "success")
	s.TriggerPolicySync()
	http.Redirect(w, r, "/events?notice="+url.QueryEscape(strconv.Itoa(validation.AffectedServerCount)+"대 서버에 예외를 단계 배포하기 시작했습니다."), http.StatusSeeOther)
}

func (s *Server) apiValidateIncidentException(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		writeProblem(w, http.StatusForbidden, "invalid csrf token")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid exception request")
		return
	}
	incidentID, err := strconv.ParseUint(strings.TrimSpace(r.FormValue("incident_id")), 10, 64)
	if err != nil || incidentID == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"valid": false, "error": "유효한 보안 이벤트가 필요합니다."})
		return
	}
	validation, err := s.validateIncidentException(r.Context(), sessionFrom(r), r.PathValue("id"), incidentID, strings.TrimSpace(r.FormValue("scope")), r.FormValue("reason"), r.FormValue("expires_in"), time.Now().UTC())
	if err != nil {
		status := http.StatusBadRequest
		var requestErr *incidentExceptionError
		if errors.As(err, &requestErr) {
			status = requestErr.Status
		}
		writeJSON(w, status, map[string]any{"valid": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"valid": true, "affected_server_count": validation.AffectedServerCount,
		"scope": validation.Scope, "rule_id": validation.Exclusion.RuleID,
		"expires_at": validation.Exclusion.ExpiresAt,
	})
}

func (s *Server) deletePolicyException(w http.ResponseWriter, r *http.Request) {
	if !s.requirePolicyForm(w, r) {
		return
	}
	if r.FormValue("confirm") != "confirmed" {
		s.renderEnterprisePolicyDetail(w, r, http.StatusBadRequest, "예외 해제 영향과 단계 배포를 확인하세요.")
		return
	}
	session := sessionFrom(r)
	policyID, exceptionID := r.PathValue("id"), r.PathValue("exception_id")
	policy, err := s.store.EnterprisePolicyByID(r.Context(), session.ScopeEnterpriseID(), policyID)
	if err != nil {
		s.writePolicyMutationError(w, r, policyID, err)
		return
	}
	configuration, err := currentPolicyConfiguration(r.Context(), s.store, policy)
	if err != nil {
		s.writePolicyMutationError(w, r, policyID, err)
		return
	}
	removed := PolicyExclusion{}
	next := make([]PolicyExclusion, 0, len(configuration.Exclusions))
	for _, exclusion := range configuration.Exclusions {
		if exclusion.ID == exceptionID && exclusion.SourceScope == PolicyScopeEnterprise {
			removed = exclusion
			continue
		}
		exclusion.Order = len(next)
		next = append(next, exclusion)
	}
	if removed.ID == "" {
		s.renderEnterprisePolicyDetail(w, r, http.StatusNotFound, "최신 정책에서 해제할 예외를 찾을 수 없습니다.")
		return
	}
	configuration.Exclusions = next
	rolloutID, err := s.createConfigurationRollout(r.Context(), policy, strings.TrimSpace(r.FormValue("expected_revision_id")), session.UserID, "incident-exception-delete", configuration)
	if err != nil {
		s.writePolicyMutationError(w, r, policyID, err)
		return
	}
	s.audit(r, session.Username, "enterprise_policy.exception_delete", policyID+":"+rolloutID+":"+exceptionID+":"+strconv.Itoa(removed.RuleID), "success")
	s.TriggerPolicySync()
	http.Redirect(w, r, userPoliciesRedirectURL(policyID, "exception", "예외 해제를 단계 배포하기 시작했습니다."), http.StatusSeeOther)
}

func (s *Server) createPolicyIPRule(w http.ResponseWriter, r *http.Request) {
	if !s.requirePolicyForm(w, r) {
		return
	}
	session := sessionFrom(r)
	policyID := r.PathValue("id")
	policy, err := s.store.EnterprisePolicyByID(r.Context(), session.ScopeEnterpriseID(), policyID)
	if err != nil {
		s.writePolicyMutationError(w, r, policyID, err)
		return
	}
	configuration, err := currentPolicyConfiguration(r.Context(), s.store, policy)
	if err != nil {
		s.writePolicyMutationError(w, r, policyID, err)
		return
	}
	action := strings.ToUpper(strings.TrimSpace(r.FormValue("action")))
	if action != PolicyIPActionBlock && action != PolicyIPActionTrust {
		s.renderAdminError(w, r, http.StatusBadRequest, "IP 동작을 확인할 수 없습니다", "차단 또는 신뢰를 선택하세요.")
		return
	}
	network, err := canonicalPolicyNetwork(r.FormValue("network"))
	if err != nil {
		s.renderAdminError(w, r, http.StatusBadRequest, "IP 주소를 확인할 수 없습니다", err.Error())
		return
	}
	reason := strings.TrimSpace(r.FormValue("reason"))
	if reason == "" {
		s.renderAdminError(w, r, http.StatusBadRequest, "변경 사유가 필요합니다", "감사 이력을 위해 IP 정책 사유를 입력하세요.")
		return
	}
	generatedID, err := nextGeneratedPolicyRuleID(configuration)
	if err != nil {
		s.renderAdminError(w, r, http.StatusConflict, "IP 정책을 추가할 수 없습니다", err.Error())
		return
	}
	var expiresAt *time.Time
	if action == PolicyIPActionTrust {
		expires := time.Now().UTC().Add(24 * time.Hour)
		if raw := strings.TrimSpace(r.FormValue("expires_at")); raw != "" {
			parsed, parseErr := localtime.ParseKST("2006-01-02T15:04", raw)
			if parseErr != nil {
				s.renderAdminError(w, r, http.StatusBadRequest, "만료 시각을 확인할 수 없습니다", "날짜와 시간을 다시 선택하세요.")
				return
			}
			expires = parsed.UTC()
		}
		expiresAt = &expires
	}
	configuration.IPRules = append(configuration.IPRules, PolicyIPRule{
		ID: randomID(), SourceScope: PolicyScopeEnterprise, Action: action, Network: network, GeneratedRuleID: generatedID,
		Reason: truncate(reason, 1024), ExpiresAt: expiresAt, CreatedBy: session.Username, Enabled: true, Order: len(configuration.IPRules),
	})
	rolloutID, err := s.createConfigurationRollout(r.Context(), policy, strings.TrimSpace(r.FormValue("expected_revision_id")), session.UserID, "ip-rule", configuration)
	if err != nil {
		s.writePolicyMutationError(w, r, policyID, err)
		return
	}
	s.audit(r, session.Username, "enterprise_policy.ip_rule_create", policyID+":"+rolloutID+":"+action+":"+network, "success")
	s.TriggerPolicySync()
	http.Redirect(w, r, userPoliciesRedirectURL(policyID, "ip", "IP 정책을 단계 배포하기 시작했습니다."), http.StatusSeeOther)
}

func (s *Server) deletePolicyIPRule(w http.ResponseWriter, r *http.Request) {
	if !s.requirePolicyForm(w, r) {
		return
	}
	session := sessionFrom(r)
	policyID, ruleID := r.PathValue("id"), r.PathValue("rule_id")
	policy, err := s.store.EnterprisePolicyByID(r.Context(), session.ScopeEnterpriseID(), policyID)
	if err != nil {
		s.writePolicyMutationError(w, r, policyID, err)
		return
	}
	configuration, err := currentPolicyConfiguration(r.Context(), s.store, policy)
	if err != nil {
		s.writePolicyMutationError(w, r, policyID, err)
		return
	}
	removed := false
	next := configuration.IPRules[:0]
	for _, rule := range configuration.IPRules {
		if rule.ID == ruleID && rule.SourceScope == PolicyScopeEnterprise {
			removed = true
			continue
		}
		rule.Order = len(next)
		next = append(next, rule)
	}
	if !removed {
		s.renderAdminError(w, r, http.StatusNotFound, "IP 정책을 찾을 수 없습니다", "최신 보호 정책을 확인하세요.")
		return
	}
	configuration.IPRules = next
	rolloutID, err := s.createConfigurationRollout(r.Context(), policy, strings.TrimSpace(r.FormValue("expected_revision_id")), session.UserID, "ip-rule-delete", configuration)
	if err != nil {
		s.writePolicyMutationError(w, r, policyID, err)
		return
	}
	s.audit(r, session.Username, "enterprise_policy.ip_rule_delete", policyID+":"+rolloutID+":"+ruleID, "success")
	s.TriggerPolicySync()
	http.Redirect(w, r, userPoliciesRedirectURL(policyID, "ip", "IP 정책 제거를 단계 배포하기 시작했습니다."), http.StatusSeeOther)
}

func userPoliciesRedirectURL(policyID, kind, notice string) string {
	query := url.Values{}
	if strings.TrimSpace(policyID) != "" {
		query.Set("policy_id", policyID)
	}
	if strings.TrimSpace(kind) != "" {
		query.Set("type", kind)
	}
	if strings.TrimSpace(notice) != "" {
		query.Set("notice", notice)
	}
	return "/user-policies?" + query.Encode()
}

func (s *Server) createPolicyUserRule(w http.ResponseWriter, r *http.Request) {
	if !s.requirePolicyForm(w, r) {
		return
	}
	session := sessionFrom(r)
	policyID := r.PathValue("id")
	policy, err := s.store.EnterprisePolicyByID(r.Context(), session.ScopeEnterpriseID(), policyID)
	if err != nil {
		s.writePolicyMutationError(w, r, policyID, err)
		return
	}
	configuration, err := currentPolicyConfiguration(r.Context(), s.store, policy)
	if err != nil {
		s.writePolicyMutationError(w, r, policyID, err)
		return
	}
	name := truncate(strings.TrimSpace(r.FormValue("name")), 255)
	if name == "" {
		s.renderAdminError(w, r, http.StatusBadRequest, "사용자 Rule 이름이 필요합니다", "운영자가 목적을 알 수 있는 이름을 입력하세요.")
		return
	}
	guided := guidedPolicyRule{
		Field: strings.TrimSpace(r.FormValue("field")), Argument: strings.TrimSpace(r.FormValue("argument")),
		Operator: strings.TrimSpace(r.FormValue("operator")), Value: strings.TrimSpace(r.FormValue("value")), Action: strings.TrimSpace(r.FormValue("action")),
	}
	existing := make([]string, 0, len(configuration.CustomRules))
	for _, rule := range configuration.CustomRules {
		existing = append(existing, rule.CanonicalSecRule)
	}
	rendered, err := mergeGuidedPolicyRules(strings.Join(existing, "\n"), []guidedPolicyRule{guided})
	if err != nil {
		s.renderAdminError(w, r, http.StatusBadRequest, "사용자 Rule을 확인할 수 없습니다", err.Error())
		return
	}
	canonical := strings.SplitN(rendered, "\n", 2)[0]
	match := customRuleID.FindStringSubmatch(canonical)
	if len(match) != 2 {
		s.renderAdminError(w, r, http.StatusInternalServerError, "사용자 Rule을 만들 수 없습니다", "안전한 Rule ID를 할당하지 못했습니다.")
		return
	}
	ruleID, _ := strconv.Atoi(match[1])
	configuration.CustomRules = append(configuration.CustomRules, PolicyCustomRule{
		ID: randomID(), SourceScope: PolicyScopeEnterprise, RuleID: ruleID, Name: name,
		Phase: secRuleActionValue(canonical, "phase"), Severity: secRuleActionValue(canonical, "severity"),
		CanonicalSecRule: canonical, Enabled: true, Order: len(configuration.CustomRules),
	})
	rolloutID, err := s.createConfigurationRollout(r.Context(), policy, strings.TrimSpace(r.FormValue("expected_revision_id")), session.UserID, "user-rule", configuration)
	if err != nil {
		s.writePolicyMutationError(w, r, policyID, err)
		return
	}
	s.audit(r, session.Username, "enterprise_policy.user_rule_create", policyID+":"+rolloutID+":"+strconv.Itoa(ruleID), "success")
	s.TriggerPolicySync()
	http.Redirect(w, r, userPoliciesRedirectURL(policyID, "rule", "사용자 Rule을 단계 배포하기 시작했습니다."), http.StatusSeeOther)
}

func (s *Server) deletePolicyUserRule(w http.ResponseWriter, r *http.Request) {
	if !s.requirePolicyForm(w, r) {
		return
	}
	if r.FormValue("confirm") != "confirmed" {
		s.renderAdminError(w, r, http.StatusBadRequest, "사용자 Rule 제거 확인이 필요합니다", "연결 서버에 새 정책이 배포됨을 확인하세요.")
		return
	}
	session := sessionFrom(r)
	policyID, customRuleID := r.PathValue("id"), r.PathValue("rule_id")
	policy, err := s.store.EnterprisePolicyByID(r.Context(), session.ScopeEnterpriseID(), policyID)
	if err != nil {
		s.writePolicyMutationError(w, r, policyID, err)
		return
	}
	configuration, err := currentPolicyConfiguration(r.Context(), s.store, policy)
	if err != nil {
		s.writePolicyMutationError(w, r, policyID, err)
		return
	}
	removed := PolicyCustomRule{}
	next := make([]PolicyCustomRule, 0, len(configuration.CustomRules))
	for _, rule := range configuration.CustomRules {
		if rule.ID == customRuleID && rule.SourceScope == PolicyScopeEnterprise {
			removed = rule
			continue
		}
		rule.Order = len(next)
		next = append(next, rule)
	}
	if removed.ID == "" {
		s.renderAdminError(w, r, http.StatusNotFound, "사용자 Rule을 찾을 수 없습니다", "최신 사용자 정책을 확인하세요.")
		return
	}
	configuration.CustomRules = next
	rolloutID, err := s.createConfigurationRollout(r.Context(), policy, strings.TrimSpace(r.FormValue("expected_revision_id")), session.UserID, "user-rule-delete", configuration)
	if err != nil {
		s.writePolicyMutationError(w, r, policyID, err)
		return
	}
	s.audit(r, session.Username, "enterprise_policy.user_rule_delete", policyID+":"+rolloutID+":"+strconv.Itoa(removed.RuleID), "success")
	s.TriggerPolicySync()
	http.Redirect(w, r, userPoliciesRedirectURL(policyID, "rule", "사용자 Rule 제거를 단계 배포하기 시작했습니다."), http.StatusSeeOther)
}

func currentPolicyConfiguration(ctx context.Context, store *Store, policy EnterprisePolicyRecord) (PolicyConfiguration, error) {
	if policy.CurrentConfiguration != nil {
		return *policy.CurrentConfiguration, nil
	}
	if policy.CurrentRevisionID == "" {
		return PolicyConfiguration{}, sql.ErrNoRows
	}
	return store.PolicyConfigurationByRevisionID(ctx, policy.CurrentRevisionID)
}

func (s *Server) apiIncidentDetail(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil || id == 0 {
		writeProblem(w, http.StatusBadRequest, "invalid incident id")
		return
	}
	incident, err := s.store.IncidentByID(r.Context(), sessionFrom(r).ScopeEnterpriseID(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeProblem(w, http.StatusNotFound, "incident not found")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "load incident")
		return
	}
	session := sessionFrom(r)
	canCreate := incident.PrimaryRuleID != "" && !isSummaryRule(incident.PrimaryRuleID)
	blockReason := ""
	affectedServerCount := 0
	affectedServers := make([]map[string]string, 0)
	currentRevisionID := ""
	availableScopes := make([]string, 0, 3)
	if canCreate && incident.PolicyID != "" {
		policy, policyErr := s.store.EnterprisePolicyByID(r.Context(), session.ScopeEnterpriseID(), incident.PolicyID)
		switch {
		case policyErr != nil:
			canCreate, blockReason = false, "현재 보호 정책을 확인할 수 없습니다."
		case policy.Status != EnterprisePolicyActive:
			canCreate, blockReason = false, "현재 운영 중인 보호 정책이 아닙니다."
		case policy.CurrentRevisionID != incident.PolicyRevision:
			canCreate, blockReason = false, "현재 정책과 다른 개정본에서 발생한 이벤트입니다."
		case policy.HasActiveRollout:
			canCreate, blockReason = false, "진행 중인 정책 배포가 끝난 뒤 예외를 검토하세요."
		default:
			currentRevisionID = policy.CurrentRevisionID
			servers, serverErr := s.store.ListPolicyServers(r.Context(), policy.EnterpriseID, policy.ID)
			if serverErr != nil {
				canCreate, blockReason = false, "영향 서버를 확인할 수 없습니다."
			} else if len(servers) == 0 {
				canCreate, blockReason = false, "연결된 서버가 없어 예외를 배포할 수 없습니다."
			} else {
				affectedServerCount = len(servers)
				for _, server := range servers {
					affectedServers = append(affectedServers, map[string]string{"id": server.ID, "name": server.Name})
				}
				if incident.MatchedVariable != "" {
					availableScopes = append(availableScopes, "input")
				}
				availableScopes = append(availableScopes, "url")
				if roleAtLeast(session.Role, RoleEnterpriseAdmin) {
					availableScopes = append(availableScopes, "global")
				}
			}
		}
	} else if canCreate {
		canCreate, blockReason = false, "이 이벤트에 연결된 보호 정책이 없습니다."
	} else {
		blockReason = "예외 처리할 수 있는 원본 탐지 Rule이 없습니다."
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"incident": incident, "related_rules": incident.Events,
		"labels":               map[string]string{"category": incident.CategoryLabel(), "country": incident.CountryLabel()},
		"can_create_exception": canCreate,
		"exception_options": map[string]any{
			"can_create": canCreate, "block_reason": blockReason, "current_revision_id": currentRevisionID,
			"affected_server_count": affectedServerCount, "affected_servers": affectedServers, "available_scopes": availableScopes,
			"can_permanent": roleAtLeast(session.Role, RoleEnterpriseAdmin),
		},
		"links": map[string]string{"server": "/servers/" + incident.AgentID, "policy": policyDetailURL(incident.PolicyID)},
	})
}
