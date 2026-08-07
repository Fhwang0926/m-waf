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
		s.renderAdminError(w, r, http.StatusInternalServerError, "시스템 정책을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	_ = s.templates.ExecuteTemplate(w, "system-policies.html", s.viewData(r, "system-policies", map[string]any{"Policies": items}))
}

func (s *Server) enterprisePolicyDetail(w http.ResponseWriter, r *http.Request) {
	s.renderEnterprisePolicyDetail(w, r, http.StatusOK, "")
}

func (s *Server) renderEnterprisePolicyDetail(w http.ResponseWriter, r *http.Request, status int, pageError string) {
	session := sessionFrom(r)
	policy, err := s.store.EnterprisePolicyByID(r.Context(), session.ScopeEnterpriseID(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.renderAdminError(w, r, http.StatusNotFound, "기업 정책을 찾을 수 없습니다", "삭제되었거나 현재 기업 범위에서 접근할 수 없는 정책입니다.")
			return
		}
		s.renderAdminError(w, r, http.StatusInternalServerError, "기업 정책을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	rollouts, err := s.store.ListPolicyRollouts(r.Context(), session.ScopeEnterpriseID(), policy.ID, 50)
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "단계 배포 이력을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	revisions, err := s.store.ListPolicyRevisions(r.Context(), session.ScopeEnterpriseID(), policy.ID, 50)
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "정책 개정본을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
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
		"Notice": r.URL.Query().Get("notice"), "Error": pageError,
	}
	if status != http.StatusOK {
		w.WriteHeader(status)
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
		s.writePolicyMutationError(w, r, policyID, err)
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
		s.writePolicyMutationError(w, r, policyID, err)
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
		s.writePolicyMutationError(w, r, policyID, err)
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
	if r.FormValue("confirm") != "confirmed" {
		s.renderEnterprisePolicyDetail(w, r, http.StatusBadRequest, "시스템 정책 기반 전환 내용을 확인해야 합니다.")
		return
	}
	expectedRevisionID := strings.TrimSpace(r.FormValue("expected_revision_id"))
	policy, err := s.store.EnterprisePolicyByID(r.Context(), session.ScopeEnterpriseID(), policyID)
	if err != nil {
		s.writePolicyMutationError(w, r, policyID, err)
		return
	}
	if policy.Status != EnterprisePolicyLegacyLocked || policy.CurrentRevisionID != expectedRevisionID {
		s.writePolicyMutationError(w, r, policyID, errors.New("enterprise policy revision changed"))
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
		s.renderEnterprisePolicyDetail(w, r, http.StatusInternalServerError, "정책 대상 서버를 불러올 수 없습니다.")
		return
	}
	policies, err := s.store.ListEnterprisePolicies(r.Context(), policy.EnterpriseID, systemPolicyServerLimit)
	if err != nil {
		s.renderEnterprisePolicyDetail(w, r, http.StatusInternalServerError, "기업 정책을 불러올 수 없습니다.")
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
		s.renderEnterprisePolicyDetail(w, r, http.StatusInternalServerError, "정책 우선순위를 계산할 수 없습니다.")
		return
	}
	serverIDs := winners[policy.ID]
	if len(serverIDs) == 0 {
		s.renderEnterprisePolicyDetail(w, r, http.StatusConflict, "현재 우선순위에서 이 정책이 적용되는 서버가 없어 전환할 수 없습니다.")
		return
	}
	serverIDs = orderIDsByServers(serverIDs, servers)
	revision, fullPath, err := s.preparePolicyRevision(targetTemplate, policy.Name, policy.Description, mode, settings, policy.CurrentRevisionID, "legacy-conversion")
	if err != nil {
		s.renderEnterprisePolicyDetail(w, r, http.StatusConflict, "기존 정책 설정을 전환할 수 없습니다: "+err.Error())
		return
	}
	rolloutID, err := s.store.ConvertLegacyEnterprisePolicy(r.Context(), policy, expectedRevisionID, targetTemplate.Key, session.UserID, revision, serverIDs)
	if err != nil {
		_ = os.Remove(fullPath)
		s.writePolicyMutationError(w, r, policyID, err)
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
	if r.FormValue("confirm") != "confirmed" {
		s.renderEnterprisePolicyDetail(w, r, http.StatusBadRequest, "정책과 패키지 롤백 내용을 확인해야 합니다.")
		return
	}
	expectedRevisionID := strings.TrimSpace(r.FormValue("expected_revision_id"))
	policy, err := s.store.EnterprisePolicyByID(r.Context(), session.ScopeEnterpriseID(), policyID)
	if err != nil {
		s.writePolicyMutationError(w, r, policyID, err)
		return
	}
	if policy.Status != EnterprisePolicyActive || policy.CurrentRevisionID != expectedRevisionID || policy.PreviousRevisionID == "" {
		s.writePolicyMutationError(w, r, policyID, errors.New("enterprise policy revision changed"))
		return
	}
	previous, err := s.store.PolicyRevisionByID(r.Context(), policy.ID, policy.PreviousRevisionID)
	if err != nil {
		s.writePolicyMutationError(w, r, policyID, err)
		return
	}
	targetTemplate, ok := splitSystemPolicyReference(s.policyCatalog, previous.SystemPolicyVersionID)
	if !ok || targetTemplate.Status == systempolicy.StatusWithdrawn {
		s.renderEnterprisePolicyDetail(w, r, http.StatusConflict, "회수되었거나 알 수 없는 시스템 정책 버전으로는 롤백할 수 없습니다.")
		return
	}
	servers, err := s.store.ListServers(r.Context(), policy.EnterpriseID, systemPolicyServerLimit)
	if err != nil {
		s.renderEnterprisePolicyDetail(w, r, http.StatusInternalServerError, "정책 대상 서버를 불러올 수 없습니다.")
		return
	}
	policies, err := s.store.ListEnterprisePolicies(r.Context(), policy.EnterpriseID, systemPolicyServerLimit)
	if err != nil {
		s.renderEnterprisePolicyDetail(w, r, http.StatusInternalServerError, "기업 정책을 불러올 수 없습니다.")
		return
	}
	winners, err := s.enterprisePolicyWinners(r.Context(), policies, servers)
	if err != nil {
		s.renderEnterprisePolicyDetail(w, r, http.StatusInternalServerError, "정책 우선순위를 계산할 수 없습니다.")
		return
	}
	serverIDs := orderIDsByServers(winners[policy.ID], servers)
	if len(serverIDs) == 0 {
		s.renderEnterprisePolicyDetail(w, r, http.StatusConflict, "현재 이 정책이 우선 적용되는 서버가 없습니다.")
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
			s.renderEnterprisePolicyDetail(w, r, http.StatusConflict, "서명된 롤백 패키지 bundle을 사용할 수 없습니다.")
			return
		}
		if _, _, err := s.catalog.ResolveCRS(server.Inventory, targetTemplate.CRSVersion); err != nil {
			s.renderEnterprisePolicyDetail(w, r, http.StatusConflict, "호환되는 롤백 패키지가 없어 실행할 수 없습니다: "+err.Error())
			return
		}
	}
	rolloutID, err := s.store.CreatePolicyRollout(r.Context(), policy, expectedRevisionID, "ROLLBACK", "QUEUED", session.UserID, nil, previous.ID, previous.SystemPolicyVersionID, serverIDs)
	if err != nil {
		s.writePolicyMutationError(w, r, policyID, err)
		return
	}
	s.audit(r, session.Username, "enterprise_policy.rollback", policyID+":"+rolloutID, "success")
	s.TriggerPolicySync()
	s.redirectEnterprisePolicy(w, r, policyID, "직전 성공 정책과 호환 CRS 패키지로 롤백을 시작했습니다.")
}

func (s *Server) requirePolicyForm(w http.ResponseWriter, r *http.Request) bool {
	if !s.validCSRF(r) {
		s.renderAdminError(w, r, http.StatusForbidden, "보안 정보가 만료되었습니다", "화면을 새로고침한 뒤 다시 시도하세요.")
		return false
	}
	if err := r.ParseForm(); err != nil {
		s.renderEnterprisePolicyDetail(w, r, http.StatusBadRequest, "입력 내용을 읽을 수 없습니다. 다시 시도하세요.")
		return false
	}
	active, err := s.store.EnterprisePolicyActive(r.Context(), sessionFrom(r).ScopeEnterpriseID(), r.PathValue("id"))
	if err != nil {
		s.renderEnterprisePolicyDetail(w, r, http.StatusInternalServerError, "기업 상태를 확인할 수 없습니다.")
		return false
	}
	if !active {
		s.renderEnterprisePolicyDetail(w, r, http.StatusConflict, "운영 종료된 기업의 정책은 변경할 수 없습니다.")
		return false
	}
	return true
}

func (s *Server) writePolicyMutationError(w http.ResponseWriter, r *http.Request, policyID string, err error) {
	if errors.Is(err, sql.ErrNoRows) || strings.Contains(err.Error(), "revision changed") || strings.Contains(err.Error(), "active rollout") {
		s.renderEnterprisePolicyDetail(w, r, http.StatusConflict, "정책 개정본 또는 단계 배포 상태가 변경되었습니다. 새로고침 후 최신 상태를 확인하고 다시 시도하세요.")
		return
	}
	s.renderEnterprisePolicyDetail(w, r, http.StatusInternalServerError, "정책 작업을 처리할 수 없습니다. 잠시 후 다시 시도하세요.")
}

func (s *Server) redirectEnterprisePolicy(w http.ResponseWriter, r *http.Request, policyID, notice string) {
	http.Redirect(w, r, "/policies/"+policyID+"?notice="+url.QueryEscape(notice), http.StatusSeeOther)
}
