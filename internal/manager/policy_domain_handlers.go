package manager

import (
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Fhwang0926/m-waf/internal/systempolicy"
)

func (s *Server) systemPolicies(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListSystemPolicyVersions(r.Context())
	if err != nil {
		http.Error(w, "load system policies", http.StatusInternalServerError)
		return
	}
	_ = s.templates.ExecuteTemplate(w, "system-policies.html", s.viewData(r, "system-policies", map[string]any{"Policies": items}))
}

func (s *Server) enterprisePolicyDetail(w http.ResponseWriter, r *http.Request) {
	session := sessionFrom(r)
	policy, err := s.store.EnterprisePolicyByID(r.Context(), session.ScopeEnterpriseID(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "load enterprise policy", http.StatusInternalServerError)
		return
	}
	rollouts, err := s.store.ListPolicyRollouts(r.Context(), session.ScopeEnterpriseID(), policy.ID, 50)
	if err != nil {
		http.Error(w, "load policy rollouts", http.StatusInternalServerError)
		return
	}
	revisions, err := s.store.ListPolicyRevisions(r.Context(), session.ScopeEnterpriseID(), policy.ID, 50)
	if err != nil {
		http.Error(w, "load policy revisions", http.StatusInternalServerError)
		return
	}
	rollbackAvailable := false
	if policy.Status == EnterprisePolicyActive && !policy.HasActiveRollout && policy.PreviousRevisionID != "" {
		previous, previousErr := s.store.PolicyRevisionByID(r.Context(), policy.ID, policy.PreviousRevisionID)
		if previousErr == nil {
			if item, ok := splitSystemPolicyReference(s.policyCatalog, previous.SystemPolicyVersionID); ok && item.Status != systempolicy.StatusWithdrawn {
				rollbackAvailable = true
			}
		}
	}
	data := map[string]any{
		"Policy": policy, "Rollouts": rollouts, "Revisions": revisions, "RollbackAvailable": rollbackAvailable,
		"Notice": r.URL.Query().Get("notice"),
	}
	_ = s.templates.ExecuteTemplate(w, "enterprise-policy.html", s.viewData(r, "policies", data))
}

func (s *Server) updateEnterprisePolicyStrategy(w http.ResponseWriter, r *http.Request) {
	if !s.requirePolicyForm(w, r) {
		return
	}
	session := sessionFrom(r)
	policyID := r.PathValue("id")
	expectedRevisionID := strings.TrimSpace(r.FormValue("expected_revision_id"))
	strategy := strings.TrimSpace(r.FormValue("update_strategy"))
	if err := s.store.UpdateEnterprisePolicyStrategy(r.Context(), session.ScopeEnterpriseID(), policyID, expectedRevisionID, strategy, session.UserID); err != nil {
		s.writePolicyMutationError(w, err)
		return
	}
	s.audit(r, session.Username, "enterprise_policy.strategy", policyID+":"+strategy, "success")
	s.TriggerPolicySync()
	s.redirectEnterprisePolicy(w, r, policyID, "업데이트 전략을 변경했습니다.")
}

func (s *Server) approveEnterprisePolicyRollout(w http.ResponseWriter, r *http.Request) {
	if !s.requirePolicyForm(w, r) {
		return
	}
	session := sessionFrom(r)
	policyID := r.PathValue("id")
	rolloutID := r.PathValue("rollout_id")
	expectedRevisionID := strings.TrimSpace(r.FormValue("expected_revision_id"))
	if err := s.store.ApprovePolicyRollout(r.Context(), session.ScopeEnterpriseID(), policyID, rolloutID, expectedRevisionID, session.UserID); err != nil {
		s.writePolicyMutationError(w, err)
		return
	}
	s.audit(r, session.Username, "enterprise_policy.rollout_approve", policyID+":"+rolloutID, "success")
	s.TriggerPolicySync()
	s.redirectEnterprisePolicy(w, r, policyID, "정책 업데이트를 승인했습니다.")
}

func (s *Server) retryEnterprisePolicyRollout(w http.ResponseWriter, r *http.Request) {
	if !s.requirePolicyForm(w, r) {
		return
	}
	session := sessionFrom(r)
	policyID := r.PathValue("id")
	rolloutID := r.PathValue("rollout_id")
	expectedRevisionID := strings.TrimSpace(r.FormValue("expected_revision_id"))
	if err := s.store.RetryPolicyRollout(r.Context(), session.ScopeEnterpriseID(), policyID, rolloutID, expectedRevisionID, session.UserID); err != nil {
		s.writePolicyMutationError(w, err)
		return
	}
	s.audit(r, session.Username, "enterprise_policy.rollout_retry", policyID+":"+rolloutID, "success")
	s.TriggerPolicySync()
	s.redirectEnterprisePolicy(w, r, policyID, "실패한 단계 배포를 다시 시작했습니다.")
}

func (s *Server) convertLegacyEnterprisePolicy(w http.ResponseWriter, r *http.Request) {
	if !s.requirePolicyForm(w, r) {
		return
	}
	session := sessionFrom(r)
	policyID := r.PathValue("id")
	expectedRevisionID := strings.TrimSpace(r.FormValue("expected_revision_id"))
	policy, err := s.store.EnterprisePolicyByID(r.Context(), session.ScopeEnterpriseID(), policyID)
	if err != nil {
		s.writePolicyMutationError(w, err)
		return
	}
	if policy.Status != EnterprisePolicyLegacyLocked || policy.CurrentRevisionID != expectedRevisionID {
		s.writePolicyMutationError(w, errors.New("enterprise policy revision changed"))
		return
	}
	targetTemplate := s.policyCatalog.Default()
	settings := policy.CurrentSettings
	settings.SchemaVersion = targetTemplate.SchemaVersion
	settings.TemplateKey = targetTemplate.Key
	settings.TemplateVersion = targetTemplate.Version
	settings.CRSTrack = targetTemplate.CRSTrack
	settings.CRSVersion = targetTemplate.CRSVersion
	settings.Target = policy.Target
	settings.AutoUpdate = false
	settings.PolicyOrigin = "legacy-conversion"
	settings.MigrationStatus = "READY"
	settings.MigratedFrom = policy.CurrentRevisionID
	mode := policy.CurrentMode
	if mode != "DetectionOnly" && mode != "On" {
		mode = targetTemplate.Defaults.Mode
	}
	if settings.ParanoiaLevel < 1 || settings.ParanoiaLevel > 4 {
		settings.ParanoiaLevel = targetTemplate.Defaults.ParanoiaLevel
	}
	if settings.InboundScore < 1 || settings.InboundScore > 100 {
		settings.InboundScore = targetTemplate.Defaults.InboundScore
	}
	servers, err := s.store.ListServers(r.Context(), policy.EnterpriseID, systemPolicyServerLimit)
	if err != nil {
		http.Error(w, "load policy target servers", http.StatusInternalServerError)
		return
	}
	policies, err := s.store.ListEnterprisePolicies(r.Context(), policy.EnterpriseID, systemPolicyServerLimit)
	if err != nil {
		http.Error(w, "load enterprise policies", http.StatusInternalServerError)
		return
	}
	candidate := policy
	candidate.Status = EnterprisePolicyActive
	candidate.CurrentRevisionID = "candidate"
	candidate.UpdatedAt = time.Now().UTC()
	eligiblePolicies := make([]EnterprisePolicyRecord, 0, len(policies))
	for _, item := range policies {
		if item.ID != policy.ID {
			eligiblePolicies = append(eligiblePolicies, item)
		}
	}
	eligiblePolicies = append(eligiblePolicies, candidate)
	winners, err := s.enterprisePolicyWinners(r.Context(), eligiblePolicies, servers)
	if err != nil {
		http.Error(w, "resolve policy priority", http.StatusInternalServerError)
		return
	}
	serverIDs := winners[policy.ID]
	if len(serverIDs) == 0 {
		http.Error(w, "기존 정책 대상을 전환할 수 없습니다.", http.StatusConflict)
		return
	}
	serverIDs = orderIDsByServers(serverIDs, servers)
	revision, fullPath, err := s.preparePolicyRevision(targetTemplate, policy.Name, policy.Description, mode, settings, policy.CurrentRevisionID, "legacy-conversion")
	if err != nil {
		http.Error(w, "기존 정책 설정을 전환할 수 없습니다: "+err.Error(), http.StatusConflict)
		return
	}
	rolloutID, err := s.store.ConvertLegacyEnterprisePolicy(r.Context(), policy, expectedRevisionID, targetTemplate.Key, session.UserID, revision, serverIDs)
	if err != nil {
		_ = os.Remove(fullPath)
		s.writePolicyMutationError(w, err)
		return
	}
	s.audit(r, session.Username, "enterprise_policy.legacy_convert", policyID+":"+rolloutID, "success")
	s.TriggerPolicySync()
	s.redirectEnterprisePolicy(w, r, policyID, "기존 정책을 시스템 정책 기반 기업 정책으로 전환하기 시작했습니다.")
}

func (s *Server) rollbackEnterprisePolicy(w http.ResponseWriter, r *http.Request) {
	if !s.requirePolicyForm(w, r) {
		return
	}
	session := sessionFrom(r)
	policyID := r.PathValue("id")
	expectedRevisionID := strings.TrimSpace(r.FormValue("expected_revision_id"))
	policy, err := s.store.EnterprisePolicyByID(r.Context(), session.ScopeEnterpriseID(), policyID)
	if err != nil {
		s.writePolicyMutationError(w, err)
		return
	}
	if policy.Status != EnterprisePolicyActive || policy.CurrentRevisionID != expectedRevisionID || policy.PreviousRevisionID == "" {
		s.writePolicyMutationError(w, errors.New("enterprise policy revision changed"))
		return
	}
	previous, err := s.store.PolicyRevisionByID(r.Context(), policy.ID, policy.PreviousRevisionID)
	if err != nil {
		s.writePolicyMutationError(w, err)
		return
	}
	targetTemplate, ok := splitSystemPolicyReference(s.policyCatalog, previous.SystemPolicyVersionID)
	if !ok || targetTemplate.Status == systempolicy.StatusWithdrawn {
		http.Error(w, "회수되었거나 알 수 없는 시스템 정책 버전으로는 롤백할 수 없습니다.", http.StatusConflict)
		return
	}
	servers, err := s.store.ListServers(r.Context(), policy.EnterpriseID, systemPolicyServerLimit)
	if err != nil {
		http.Error(w, "load policy target servers", http.StatusInternalServerError)
		return
	}
	policies, err := s.store.ListEnterprisePolicies(r.Context(), policy.EnterpriseID, systemPolicyServerLimit)
	if err != nil {
		http.Error(w, "load enterprise policies", http.StatusInternalServerError)
		return
	}
	winners, err := s.enterprisePolicyWinners(r.Context(), policies, servers)
	if err != nil {
		http.Error(w, "resolve policy targets", http.StatusInternalServerError)
		return
	}
	serverIDs := orderIDsByServers(winners[policy.ID], servers)
	if len(serverIDs) == 0 {
		http.Error(w, "현재 이 정책이 우선 적용되는 서버가 없습니다.", http.StatusConflict)
		return
	}
	serverByID := make(map[string]ServerRecord, len(servers))
	for _, server := range servers {
		serverByID[server.ID] = server
	}
	for _, serverID := range serverIDs {
		server := serverByID[serverID]
		if normalizeCRSVersion(server.Inventory.CRSVersion) == normalizeCRSVersion(targetTemplate.CRSVersion) {
			continue
		}
		if s.catalog == nil {
			http.Error(w, "서명된 롤백 패키지 bundle을 사용할 수 없습니다.", http.StatusConflict)
			return
		}
		if _, _, err := s.catalog.ResolveCRS(server.Inventory, targetTemplate.CRSVersion); err != nil {
			http.Error(w, "호환되는 롤백 패키지가 없어 실행할 수 없습니다: "+err.Error(), http.StatusConflict)
			return
		}
	}
	rolloutID, err := s.store.CreatePolicyRollout(r.Context(), policy, expectedRevisionID, "ROLLBACK", "QUEUED", session.UserID, nil, previous.ID, previous.SystemPolicyVersionID, serverIDs)
	if err != nil {
		s.writePolicyMutationError(w, err)
		return
	}
	s.audit(r, session.Username, "enterprise_policy.rollback", policyID+":"+rolloutID, "success")
	s.TriggerPolicySync()
	s.redirectEnterprisePolicy(w, r, policyID, "직전 성공 정책과 호환 CRS 패키지로 롤백을 시작했습니다.")
}

func (s *Server) requirePolicyForm(w http.ResponseWriter, r *http.Request) bool {
	if !s.validCSRF(r) {
		http.Error(w, "invalid csrf token", http.StatusForbidden)
		return false
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return false
	}
	return true
}

func (s *Server) writePolicyMutationError(w http.ResponseWriter, err error) {
	if errors.Is(err, sql.ErrNoRows) || strings.Contains(err.Error(), "revision changed") || strings.Contains(err.Error(), "active rollout") {
		http.Error(w, "정책 개정본 또는 rollout 상태가 변경되었습니다. 화면을 새로고침한 뒤 다시 시도하세요.", http.StatusConflict)
		return
	}
	http.Error(w, "정책 작업을 처리할 수 없습니다.", http.StatusInternalServerError)
}

func (s *Server) redirectEnterprisePolicy(w http.ResponseWriter, r *http.Request, policyID, notice string) {
	http.Redirect(w, r, "/policies/"+policyID+"?notice="+url.QueryEscape(notice), http.StatusSeeOther)
}
