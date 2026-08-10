package manager

import (
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/Fhwang0926/m-waf/internal/model"
	"github.com/Fhwang0926/m-waf/internal/systempolicy"
)

type policyRolloutView struct {
	Rollout PolicyRolloutRecord
	Targets []PolicyRolloutTargetRecord
}

type systemPolicyVersionView struct {
	SystemPolicyVersionRecord
	IsCurrent  bool
	IsBaseline bool
}

type systemPolicyOperationsSummary struct {
	PublishedVersionCount int
	AdoptedPolicyCount    int
	PendingUpdateCount    int
	ActiveRolloutCount    int
	FailedRolloutCount    int
}

type systemPolicyLifecycleView struct {
	HasSources             bool
	HasCurrent             bool
	HasNewSource           bool
	CurrentID              string
	CurrentName            string
	CurrentCRSVersion      string
	CurrentEnterpriseCount int
	CurrentServerCount     int
	LatestSourceID         string
	LatestSourceVersion    string
	CandidateSourceID      string
	CreateLabel            string
	CreateURL              string
}

type systemPolicyPublishedResult struct {
	Found  bool
	Policy SystemPolicyVersionRecord
	Impact migrationStrategyImpact
}

func (s *Server) systemPolicies(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListSystemPolicyVersions(r.Context())
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "시스템 정책을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	enterprisePolicies, err := s.store.ListEnterprisePolicies(r.Context(), "", systemPolicyServerLimit)
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "기업 정책 운영 현황을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	query := strings.ToLower(truncate(strings.TrimSpace(r.URL.Query().Get("q")), 255))
	statusFilter := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("status")))
	if statusFilter != "PUBLISHED" && statusFilter != "DEPRECATED" && statusFilter != "WITHDRAWN" {
		statusFilter = ""
	}
	tab := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("tab")))
	if tab != "history" {
		tab = "policies"
	}
	if query != "" || statusFilter != "" {
		tab = "history"
	}
	defaultTemplate := s.defaultSystemPolicyTemplate(r.Context())
	defaultReference := defaultTemplate.Reference()
	allVersions := make([]systemPolicyVersionView, 0, len(items))
	summary := systemPolicyOperationsSummary{}
	for _, item := range items {
		latest, exists := s.latestSystemPolicyTemplate(r.Context(), item.Key)
		current := exists && latest.Reference() == item.ID
		if current && item.Status == systempolicy.StatusPublished {
			summary.PublishedVersionCount++
		}
		allVersions = append(allVersions, systemPolicyVersionView{SystemPolicyVersionRecord: item, IsCurrent: current, IsBaseline: item.ID == defaultReference})
	}
	currentPolicy := systemPolicyVersionView{}
	hasCurrentPolicy := false
	for _, item := range allVersions {
		if !item.IsBaseline {
			continue
		}
		currentPolicy = item
		hasCurrentPolicy = true
		break
	}
	versions := make([]systemPolicyVersionView, 0, len(allVersions))
	historyTotal := 0
	for _, item := range allVersions {
		if item.IsBaseline {
			continue
		}
		historyTotal++
		if statusFilter != "" && item.Status != statusFilter {
			continue
		}
		haystack := strings.ToLower(item.Name + " " + item.Description + " " + item.Key + " " + item.CRSTrack + " " + item.CRSVersion)
		if query != "" && !strings.Contains(haystack, query) {
			continue
		}
		versions = append(versions, item)
	}
	strategyImpact := migrationStrategyImpact{}
	for _, policy := range enterprisePolicies {
		if policy.CurrentSystemPolicyID != "" {
			summary.AdoptedPolicyCount++
		}
		if policy.HasUpdate() {
			summary.PendingUpdateCount++
		}
		if policy.HasActiveRollout {
			summary.ActiveRolloutCount++
		}
		if policy.LatestRolloutStatus == "FAILED" {
			summary.FailedRolloutCount++
		}
		switch policy.UpdateStrategy {
		case PolicyStrategyAutomatic:
			strategyImpact.Automatic++
		case PolicyStrategyManual:
			strategyImpact.Manual++
		case PolicyStrategyPinned:
			strategyImpact.Pinned++
		}
	}
	lifecycle := buildSystemPolicyLifecycle(items, s.allPolicySources(), defaultTemplate)
	publishedResult := systemPolicyPublishedResult{Impact: strategyImpact}
	publishedReference := truncate(strings.TrimSpace(r.URL.Query().Get("published")), 255)
	for _, item := range items {
		if item.ID == publishedReference {
			publishedResult.Found = true
			publishedResult.Policy = item
			break
		}
	}
	data := map[string]any{
		"Versions": versions, "HistoryTotal": historyTotal, "ShowHistorySearch": historyTotal > 5 || query != "" || statusFilter != "",
		"CurrentPolicy": currentPolicy, "HasCurrentPolicy": hasCurrentPolicy, "Summary": summary,
		"Lifecycle": lifecycle, "PublishedResult": publishedResult,
		"Tab": tab, "FilterQuery": r.URL.Query().Get("q"), "FilterStatus": statusFilter, "Notice": r.URL.Query().Get("notice"), "ErrorNotice": r.URL.Query().Get("error"),
	}
	_ = s.templates.ExecuteTemplate(w, "system-policies.html", s.viewData(r, "system-policies", data))
}

func (s *Server) systemPolicyAdoptions(w http.ResponseWriter, r *http.Request) {
	policyID := truncate(strings.TrimSpace(r.PathValue("id")), 255)
	versions, err := s.store.ListSystemPolicyVersions(r.Context())
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "시스템 정책 적용 현황을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	var selected SystemPolicyVersionRecord
	found := false
	for _, version := range versions {
		if version.ID == policyID {
			selected = version
			found = true
			break
		}
	}
	if !found {
		s.renderAdminError(w, r, http.StatusNotFound, "시스템 정책을 찾을 수 없습니다", "삭제되었거나 존재하지 않는 시스템 정책입니다.")
		return
	}
	items, err := s.store.ListEnterprisePolicies(r.Context(), "", systemPolicyServerLimit)
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "기업 정책 적용 현황을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	policies := make([]EnterprisePolicyRecord, 0, len(items))
	for _, item := range items {
		if item.CurrentSystemPolicyID == policyID {
			policies = append(policies, item)
		}
	}
	data := map[string]any{"Policy": selected, "Policies": policies}
	_ = s.templates.ExecuteTemplate(w, "system-policy-adoptions.html", s.viewData(r, "system-policies", data))
}

func buildSystemPolicyLifecycle(items []SystemPolicyVersionRecord, sources []model.PolicySourceArtifact, current systempolicy.Template) systemPolicyLifecycleView {
	view := systemPolicyLifecycleView{HasSources: len(sources) != 0, CreateLabel: "CRS 관리", CreateURL: "/open-source-policies"}
	if current.Key == "" {
		return view
	}
	view.HasCurrent = true
	view.CurrentID = current.Reference()
	view.CurrentName = current.Name
	view.CurrentCRSVersion = current.CRSVersion
	for _, item := range items {
		if item.ID == view.CurrentID {
			view.CurrentEnterpriseCount = item.EnterpriseCount
			view.CurrentServerCount = item.ServerCount
			break
		}
	}
	for _, source := range sources {
		if current.CRSTrack != "" && source.Channel != "" && !strings.EqualFold(source.Channel, current.CRSTrack) {
			continue
		}
		if view.LatestSourceID == "" {
			view.LatestSourceID = source.ID
			view.LatestSourceVersion = source.Version
		}
		if sourceMatchesSystemPolicy(source, current) {
			continue
		}
		if newerCRSVersion(source.Version, current.CRSVersion) || normalizeCRSVersion(source.Version) == normalizeCRSVersion(current.CRSVersion) {
			view.HasNewSource = true
			view.CandidateSourceID = source.ID
			break
		}
	}
	if view.HasNewSource {
		view.CreateLabel = "시스템 정책 검토"
		view.CreateURL = "/system-policies/migrations/new?base=" + url.QueryEscape(view.CurrentID) + "&source_id=" + url.QueryEscape(view.CandidateSourceID)
	} else if current.Defaults.CRSSource != nil && current.Defaults.CRSSource.ID != "" {
		view.CreateLabel = "시스템 정책 수정"
		view.CreateURL = "/system-policies/migrations/new?base=" + url.QueryEscape(view.CurrentID) + "&source_id=" + url.QueryEscape(current.Defaults.CRSSource.ID)
	} else {
		view.CreateLabel = "CRS 관리"
		view.CreateURL = "/open-source-policies"
	}
	return view
}

func (s *Server) enterprisePolicyDetail(w http.ResponseWriter, r *http.Request) {
	if strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("tab")), "rules") {
		http.Redirect(w, r, userPoliciesRedirectURL(r.PathValue("id"), "all", ""), http.StatusSeeOther)
		return
	}
	s.renderEnterprisePolicyDetail(w, r, http.StatusOK, "")
}

func enterprisePolicyDetailTab(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "servers", "effective", "rollouts", "revisions":
		return value
	default:
		return "overview"
	}
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
	tab := enterprisePolicyDetailTab(r.URL.Query().Get("tab"))
	if returnTab := strings.TrimSpace(r.FormValue("return_tab")); returnTab != "" {
		tab = enterprisePolicyDetailTab(returnTab)
	}
	var members []ServerRecord
	var serverChoices []policyServerChoice
	var rolloutViews []policyRolloutView
	var revisions []PolicyRevisionRecord
	rollbackAvailable := false
	switch tab {
	case "servers":
		members, err = s.store.ListPolicyServers(r.Context(), policy.EnterpriseID, policy.ID)
		if err != nil {
			s.renderAdminError(w, r, http.StatusInternalServerError, "연결 서버를 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
			return
		}
		servers, serverErr := s.store.ListServers(r.Context(), policy.EnterpriseID, systemPolicyServerLimit)
		if serverErr != nil {
			s.renderAdminError(w, r, http.StatusInternalServerError, "보호 서버를 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
			return
		}
		serverChoices = make([]policyServerChoice, 0, len(servers))
		for _, server := range servers {
			if !server.Revoked && server.EnterprisePolicyID != policy.ID {
				serverChoices = append(serverChoices, policyServerChoice{Server: server})
			}
		}
	case "rollouts":
		rollouts, rolloutErr := s.store.ListPolicyRollouts(r.Context(), session.ScopeEnterpriseID(), policy.ID, 50)
		if rolloutErr != nil {
			s.renderAdminError(w, r, http.StatusInternalServerError, "단계 배포 이력을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
			return
		}
		rolloutViews = make([]policyRolloutView, 0, len(rollouts))
		for _, rollout := range rollouts {
			targets, targetErr := s.store.ListPolicyRolloutTargets(r.Context(), rollout.ID)
			if targetErr != nil {
				s.renderAdminError(w, r, http.StatusInternalServerError, "서버별 단계 배포 결과를 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
				return
			}
			rolloutViews = append(rolloutViews, policyRolloutView{Rollout: rollout, Targets: targets})
		}
	case "revisions":
		revisions, err = s.store.ListPolicyRevisions(r.Context(), session.ScopeEnterpriseID(), policy.ID, 50)
		if err != nil {
			s.renderAdminError(w, r, http.StatusInternalServerError, "정책 개정본을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
			return
		}
	case "overview":
		if policy.Status == EnterprisePolicyActive && !policy.HasActiveRollout && policy.PreviousRevisionID != "" {
			previous, previousErr := s.store.PolicyRevisionByID(r.Context(), policy.ID, policy.PreviousRevisionID)
			if previousErr == nil {
				if item, ok := s.systemPolicyTemplate(r.Context(), previous.SystemPolicyVersionID); ok && item.Status != systempolicy.StatusWithdrawn {
					rollbackAvailable = true
				}
			}
		}
	}
	data := map[string]any{
		"Tab": tab, "Policy": policy, "PolicyServers": members, "PolicyServerChoices": serverChoices, "Rollouts": rolloutViews, "Revisions": revisions, "RollbackAvailable": rollbackAvailable,
		"Notice": r.URL.Query().Get("notice"), "Error": pageError, "ScopeLabel": policy.EnterpriseName,
	}
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
	_ = s.templates.ExecuteTemplate(w, "enterprise-policy.html", s.viewData(r, "policies", data))
}

func (s *Server) updateEnterprisePolicyServers(w http.ResponseWriter, r *http.Request) {
	if !s.requirePolicyForm(w, r) {
		return
	}
	policyID := r.PathValue("id")
	policy, err := s.store.EnterprisePolicyByID(r.Context(), sessionFrom(r).ScopeEnterpriseID(), policyID)
	if err != nil {
		s.writePolicyMutationError(w, r, policyID, err)
		return
	}
	if r.FormValue("confirm") != "confirmed" || len(r.Form["server_ids"]) == 0 {
		s.renderEnterprisePolicyDetail(w, r, http.StatusBadRequest, "이동할 서버와 영향을 확인해야 합니다.")
		return
	}
	session := sessionFrom(r)
	rolloutID, count, err := s.store.CreatePolicyMembershipRollout(r.Context(), policy, session.UserID, r.Form["server_ids"])
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || strings.Contains(err.Error(), "active") {
			s.renderEnterprisePolicyDetail(w, r, http.StatusConflict, "선택한 서버의 정책 또는 배포 상태가 변경되었습니다. 새로고침 후 다시 확인하세요.")
			return
		}
		s.renderEnterprisePolicyDetail(w, r, http.StatusInternalServerError, "서버 정책 이동을 시작할 수 없습니다. 잠시 후 다시 시도하세요.")
		return
	}
	if count == 0 {
		s.redirectEnterprisePolicy(w, r, policyID, "선택한 서버는 이미 이 보호 정책에 연결되어 있습니다.")
		return
	}
	s.audit(r, session.Username, "enterprise_policy.servers_assign", policyID+":"+rolloutID, "success")
	s.TriggerPolicySync()
	s.redirectEnterprisePolicy(w, r, policyID, strconv.Itoa(count)+"대 서버의 정책 이동을 시작했습니다.")
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
	targetTemplate := s.defaultSystemPolicyTemplate(r.Context())
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
	serverIDs, err := s.store.ListPolicyServerIDs(r.Context(), policy.EnterpriseID, policy.ID)
	if err != nil {
		s.renderEnterprisePolicyDetail(w, r, http.StatusInternalServerError, "정책 연결 서버를 불러올 수 없습니다.")
		return
	}
	if len(serverIDs) == 0 {
		s.renderEnterprisePolicyDetail(w, r, http.StatusConflict, "이 정책에 연결된 서버가 없어 전환할 수 없습니다.")
		return
	}
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
	targetTemplate, ok := s.systemPolicyTemplate(r.Context(), previous.SystemPolicyVersionID)
	if !ok || targetTemplate.Status == systempolicy.StatusWithdrawn {
		s.renderEnterprisePolicyDetail(w, r, http.StatusConflict, "회수되었거나 알 수 없는 CRS 기준으로는 롤백할 수 없습니다.")
		return
	}
	serverIDs, err := s.store.ListPolicyServerIDs(r.Context(), policy.EnterpriseID, policy.ID)
	if err != nil {
		s.renderEnterprisePolicyDetail(w, r, http.StatusInternalServerError, "정책 연결 서버를 불러올 수 없습니다.")
		return
	}
	if len(serverIDs) == 0 {
		s.renderEnterprisePolicyDetail(w, r, http.StatusConflict, "이 정책에 연결된 서버가 없습니다.")
		return
	}
	servers, err := s.store.ListServers(r.Context(), policy.EnterpriseID, systemPolicyServerLimit)
	if err != nil {
		s.renderEnterprisePolicyDetail(w, r, http.StatusInternalServerError, "정책 연결 서버의 호환성을 확인할 수 없습니다.")
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
	query := url.Values{"notice": []string{notice}}
	if tab := enterprisePolicyDetailTab(r.FormValue("return_tab")); tab != "overview" {
		query.Set("tab", tab)
	}
	http.Redirect(w, r, "/policies/"+policyID+"?"+query.Encode(), http.StatusSeeOther)
}
