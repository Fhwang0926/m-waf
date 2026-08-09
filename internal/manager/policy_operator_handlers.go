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

func (s *Server) ipRules(w http.ResponseWriter, r *http.Request) {
	requestedEnterprise := r.URL.Query().Get("enterprise_id")
	enterpriseID, ok := s.effectiveEnterpriseFilter(r, requestedEnterprise)
	if !ok {
		s.renderAdminError(w, r, http.StatusBadRequest, "기업 범위를 확인할 수 없습니다", "유효한 기업을 선택하세요.")
		return
	}
	policies, err := s.store.ListEnterprisePolicies(r.Context(), enterpriseID, 5000)
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "IP 정책을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	items := make([]policyIPRuleView, 0)
	for _, policy := range policies {
		if policy.Status != EnterprisePolicyActive || policy.CurrentConfiguration == nil {
			continue
		}
		for _, rule := range policy.CurrentConfiguration.IPRules {
			if rule.SourceScope == PolicyScopeEnterprise {
				items = append(items, policyIPRuleView{Policy: policy, Rule: rule})
			}
		}
	}
	enterprises, _ := s.store.ListEnterprises(r.Context())
	data := map[string]any{
		"Policies": policies, "IPRules": items, "Now": time.Now().UTC(), "Enterprises": enterprises,
		"FilterEnterprise": enterpriseID, "Notice": r.URL.Query().Get("notice"),
	}
	_ = s.templates.ExecuteTemplate(w, "ip-rules.html", s.viewData(r, "ip-rules", data))
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
	policy, err := s.store.EnterprisePolicyByID(r.Context(), session.ScopeEnterpriseID(), policyID)
	if err != nil {
		s.writePolicyMutationError(w, r, policyID, err)
		return
	}
	incident, err := s.store.IncidentByID(r.Context(), session.ScopeEnterpriseID(), incidentID)
	if err != nil || incident.PolicyID != policy.ID || incident.PolicyRevision != policy.CurrentRevisionID {
		s.renderAdminError(w, r, http.StatusConflict, "정책 상태가 변경되었습니다", "최신 이벤트와 정책 상태를 확인한 뒤 다시 시도하세요.")
		return
	}
	ruleID, err := strconv.Atoi(incident.PrimaryRuleID)
	if err != nil || ruleID <= 0 || isSummaryRule(incident.PrimaryRuleID) {
		s.renderAdminError(w, r, http.StatusConflict, "자동 예외를 만들 수 없습니다", "이 이벤트에는 예외 처리할 수 있는 원본 탐지 Rule이 없습니다.")
		return
	}
	configuration, err := currentPolicyConfiguration(r.Context(), s.store, policy)
	if err != nil {
		s.writePolicyMutationError(w, r, policyID, err)
		return
	}
	scope := strings.TrimSpace(r.FormValue("scope"))
	exclusion := PolicyExclusion{ID: randomID(), SourceScope: PolicyScopeEnterprise, RuleID: ruleID, Enabled: true, Reason: "보안 이벤트 " + strconv.FormatUint(incident.ID, 10), Order: len(configuration.Exclusions)}
	switch scope {
	case "input":
		if incident.MatchedVariable == "" {
			s.renderAdminError(w, r, http.StatusBadRequest, "입력 항목 예외를 만들 수 없습니다", "탐지 입력 위치가 없는 이벤트입니다. URL 범위 예외를 선택하세요.")
			return
		}
		exclusion.Type, exclusion.LoadStage, exclusion.Target = PolicyExclusionTarget, PolicyExclusionBefore, incident.MatchedVariable
		exclusion.Conditions = []PolicyExclusionCondition{{Field: "REQUEST_URI", Operator: "@streq", Value: incident.URI}}
	case "url":
		exclusion.Type, exclusion.LoadStage = PolicyExclusionRule, PolicyExclusionBefore
		exclusion.Conditions = []PolicyExclusionCondition{{Field: "REQUEST_URI", Operator: "@streq", Value: incident.URI}}
	case "global":
		if r.FormValue("confirm") != "confirmed" {
			s.renderAdminError(w, r, http.StatusBadRequest, "전체 범위 확인이 필요합니다", "모든 요청에서 Rule을 제외하는 내용을 확인하세요.")
			return
		}
		exclusion.Type, exclusion.LoadStage = PolicyExclusionRule, PolicyExclusionAfter
	default:
		s.renderAdminError(w, r, http.StatusBadRequest, "예외 범위를 확인할 수 없습니다", "입력 항목, URL 또는 모든 요청 중 하나를 선택하세요.")
		return
	}
	if exclusion.LoadStage == PolicyExclusionBefore {
		exclusion.GeneratedRuleID, err = nextGeneratedPolicyRuleID(configuration)
		if err != nil {
			s.renderAdminError(w, r, http.StatusConflict, "예외를 추가할 수 없습니다", err.Error())
			return
		}
	}
	configuration.Exclusions = append(configuration.Exclusions, exclusion)
	rolloutID, err := s.createConfigurationRollout(r.Context(), policy, strings.TrimSpace(r.FormValue("expected_revision_id")), session.UserID, "incident-exception", configuration)
	if err != nil {
		s.writePolicyMutationError(w, r, policyID, err)
		return
	}
	s.audit(r, session.Username, "enterprise_policy.incident_exception", policyID+":"+rolloutID+":"+strconv.FormatUint(incident.ID, 10)+":"+scope, "success")
	s.TriggerPolicySync()
	http.Redirect(w, r, "/events?notice="+url.QueryEscape("선택한 범위의 예외를 단계 배포하기 시작했습니다."), http.StatusSeeOther)
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
	http.Redirect(w, r, "/ip-rules?notice="+url.QueryEscape("IP 정책을 단계 배포하기 시작했습니다."), http.StatusSeeOther)
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
	http.Redirect(w, r, "/ip-rules?notice="+url.QueryEscape("IP 정책 제거를 단계 배포하기 시작했습니다."), http.StatusSeeOther)
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
	writeJSON(w, http.StatusOK, map[string]any{
		"incident": incident, "related_rules": incident.Events,
		"labels":               map[string]string{"category": incident.CategoryLabel(), "country": incident.CountryLabel()},
		"can_create_exception": incident.PrimaryRuleID != "" && !isSummaryRule(incident.PrimaryRuleID),
		"links":                map[string]string{"server": "/servers/" + incident.AgentID, "policy": policyDetailURL(incident.PolicyID)},
	})
}
