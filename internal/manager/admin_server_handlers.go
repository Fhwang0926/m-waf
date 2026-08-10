package manager

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/Fhwang0926/m-waf/internal/model"
)

var allowedAgentCommands = map[string]string{
	"agent_restart":        "Agent 재시작",
	"agent_stop":           "Agent 중지",
	"server_restart":       "서버 재시작",
	"server_stop":          "서버 종료",
	"web_control_standard": "자동 설정 검사·재적용 사용",
	"web_control_hooks":    "사용자 지정 실행 파일 사용",
}

func (s *Server) agentRollbackTarget(ctx context.Context, server ServerRecord, currentAgentID string) (model.PackageArtifact, bool, error) {
	if s.catalog == nil || currentAgentID == "" {
		return model.PackageArtifact{}, false, nil
	}
	current, ok := s.catalog.Artifact(currentAgentID)
	if !ok || current.Kind != "agent" || current.Version != strings.TrimSpace(server.Inventory.AgentVersion) {
		return model.PackageArtifact{}, false, nil
	}
	target, err := s.catalog.RollbackAgent(currentAgentID)
	if err != nil || target.ID == current.ID || target.Version == current.Version {
		return model.PackageArtifact{}, false, nil
	}
	confirmed, err := s.store.AppliedAgentUpgradeConfirmed(ctx, server.ID, currentAgentID)
	if err != nil {
		return model.PackageArtifact{}, false, err
	}
	return target, confirmed, nil
}

func validServerRevokeConfirmation(serverName, confirmation string) bool {
	return serverName != "" && strings.TrimSpace(confirmation) == serverName
}

func (s *Server) createServerCommand(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		s.renderAdminError(w, r, http.StatusForbidden, "보안 정보가 만료되었습니다", "화면을 새로고침한 뒤 다시 시도하세요.")
		return
	}
	command := strings.TrimSpace(r.FormValue("command"))
	label, ok := allowedAgentCommands[command]
	if !ok || r.FormValue("confirm") != "confirmed" {
		s.renderServers(w, r, http.StatusBadRequest, "운영 명령과 서비스 영향 확인을 확인하세요.")
		return
	}
	if (command == "agent_stop" || command == "server_stop") && r.FormValue("recovery_confirm") != "confirmed" {
		s.renderServers(w, r, http.StatusBadRequest, "중지 명령은 외부 콘솔 또는 전원 제어를 통한 복구 가능성을 추가로 확인해야 합니다.")
		return
	}
	session := sessionFrom(r)
	serverID := r.PathValue("id")
	commandID, err := s.store.QueueCommand(r.Context(), session.ScopeEnterpriseID(), serverID, command, session.UserID)
	if err != nil {
		status := http.StatusConflict
		if errors.Is(err, sql.ErrNoRows) {
			status = http.StatusNotFound
		}
		s.renderServers(w, r, status, "명령을 예약할 수 없습니다: "+err.Error())
		return
	}
	s.audit(r, session.Username, "server.command", serverID+":"+commandID+":"+command, "success")
	redirectPath := "/servers"
	separator := "?"
	if returnTab := strings.TrimSpace(r.FormValue("return_tab")); returnTab != "" {
		redirectPath = "/servers/" + serverID + "?tab=" + url.QueryEscape(serverDetailTab(returnTab))
		separator = "&"
	} else if command == "web_control_standard" || command == "web_control_hooks" {
		redirectPath = "/servers/" + serverID + "?tab=packages"
		separator = "&"
	}
	http.Redirect(w, r, redirectPath+separator+"notice="+url.QueryEscape(label+" 명령이 예약되었습니다."), http.StatusSeeOther)
}

func (s *Server) deployServerPackages(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		s.renderAdminError(w, r, http.StatusForbidden, "보안 정보가 만료되었습니다", "화면을 새로고침한 뒤 다시 시도하세요.")
		return
	}
	if s.catalog == nil {
		s.renderServers(w, r, http.StatusServiceUnavailable, "서명된 package bundle을 사용할 수 없어 배포할 수 없습니다.")
		return
	}
	if r.FormValue("confirm") != "confirmed" {
		s.renderServers(w, r, http.StatusBadRequest, "패키지 배포의 서비스 영향을 확인해야 합니다.")
		return
	}
	session := sessionFrom(r)
	serverID := r.PathValue("id")
	server, err := s.store.ServerByID(r.Context(), session.ScopeEnterpriseID(), serverID)
	if err != nil || server.Revoked {
		s.renderServers(w, r, http.StatusNotFound, "서버를 찾을 수 없거나 이미 등록 해제되었습니다.")
		return
	}
	if server.Inventory.InstallationMode == "manual" {
		s.renderServers(w, r, http.StatusConflict, "수동 Connector 서버는 Manager가 모듈 패키지를 교체하지 않습니다. 기존 Connector를 유지하고 별도 유지보수 절차로 Agent를 갱신하세요.")
		return
	}
	operation := strings.TrimSpace(r.FormValue("operation"))
	var agentID, moduleID string
	switch operation {
	case "update":
		agentPackage, modulePackage, resolveErr := s.catalog.Resolve(server.Inventory)
		if resolveErr != nil {
			s.renderServers(w, r, http.StatusUnprocessableEntity, "업데이트 패키지를 찾을 수 없습니다: "+resolveErr.Error())
			return
		}
		agentID, moduleID = agentPackage.ID, modulePackage.ID
	case "rollback":
		currentAgent, currentModule, currentErr := s.store.CurrentPackageIDs(r.Context(), serverID)
		if currentErr != nil {
			s.renderServers(w, r, http.StatusInternalServerError, "현재 패키지를 확인할 수 없습니다.")
			return
		}
		agentPackage, modulePackage, rollbackErr := s.catalog.Rollback(currentAgent, currentModule)
		if rollbackErr != nil {
			s.renderServers(w, r, http.StatusUnprocessableEntity, "롤백 패키지를 찾을 수 없습니다: "+rollbackErr.Error())
			return
		}
		agentID, moduleID = agentPackage.ID, modulePackage.ID
	default:
		s.renderServers(w, r, http.StatusBadRequest, "지원하지 않는 패키지 작업입니다.")
		return
	}
	deploymentID, err := s.store.AssignPackagesWithControl(r.Context(), session.ScopeEnterpriseID(), serverID, agentID, moduleID, session.UserID, server.Inventory.WebServerControl)
	if err != nil {
		s.renderServers(w, r, http.StatusConflict, "패키지 배포를 예약할 수 없습니다: "+err.Error())
		return
	}
	s.audit(r, session.Username, "package."+operation, serverID+":"+deploymentID, "success")
	http.Redirect(w, r, "/servers/"+serverID+"?tab=packages&notice="+url.QueryEscape("Agent와 WAF 모듈 "+map[string]string{"update": "업데이트", "rollback": "롤백"}[operation]+"가 예약되었습니다."), http.StatusSeeOther)
}

func (s *Server) deployServerAgent(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		s.renderAdminError(w, r, http.StatusForbidden, "보안 정보가 만료되었습니다", "화면을 새로고침한 뒤 다시 시도하세요.")
		return
	}
	if s.catalog == nil {
		s.renderAdminError(w, r, http.StatusServiceUnavailable, "Agent 설치 파일을 사용할 수 없습니다", "Manager의 서명 bundle을 확인하세요.")
		return
	}
	if r.FormValue("confirm") != "confirmed" {
		s.renderAdminError(w, r, http.StatusBadRequest, "Agent 업데이트 영향을 확인해야 합니다", "Agent 프로세스가 한 번 재시작됩니다.")
		return
	}
	session := sessionFrom(r)
	serverID := r.PathValue("id")
	server, err := s.store.ServerByID(r.Context(), session.ScopeEnterpriseID(), serverID)
	if err != nil || server.Revoked {
		s.renderAdminError(w, r, http.StatusNotFound, "서버를 찾을 수 없습니다", "등록 해제되었거나 현재 기업 범위에서 접근할 수 없는 서버입니다.")
		return
	}
	if !agentPackageManagementReady(server.Inventory) {
		s.renderAdminError(w, r, http.StatusConflict, "Agent 단독 업데이트 전환이 필요합니다", "패키지 탭의 1회 전환 명령을 서버에서 먼저 실행하세요.")
		return
	}
	operation := strings.TrimSpace(r.FormValue("operation"))
	var target model.PackageArtifact
	switch operation {
	case "update":
		target, err = s.catalog.ResolveAgent(server.Inventory)
		if err == nil {
			if _, rollbackErr := s.catalog.RollbackAgent(target.ID); rollbackErr != nil {
				err = errors.New("직전 검증 Agent가 bundle에 없어 안전한 업데이트를 예약할 수 없습니다")
			}
		}
	case "rollback":
		currentAgentID, _, currentErr := s.store.CurrentPackageIDs(r.Context(), serverID)
		if currentErr != nil {
			s.renderAdminError(w, r, http.StatusInternalServerError, "현재 Agent 상태를 확인할 수 없습니다", "잠시 후 다시 시도하세요.")
			return
		}
		var rollbackReady bool
		target, rollbackReady, err = s.agentRollbackTarget(r.Context(), server, currentAgentID)
		if err != nil {
			s.renderAdminError(w, r, http.StatusInternalServerError, "Agent 업그레이드 이력을 확인할 수 없습니다", "잠시 후 다시 시도하세요.")
			return
		}
		if !rollbackReady {
			s.renderAdminError(w, r, http.StatusConflict, "롤백할 이전 Agent가 없습니다", "성공한 Agent 업그레이드와 호환 이전 버전이 모두 확인된 경우에만 롤백할 수 있습니다.")
			return
		}
	default:
		s.renderAdminError(w, r, http.StatusBadRequest, "지원하지 않는 Agent 작업입니다", "업데이트 또는 롤백을 선택하세요.")
		return
	}
	if err != nil {
		s.renderAdminError(w, r, http.StatusUnprocessableEntity, "호환 Agent 패키지를 찾을 수 없습니다", err.Error())
		return
	}
	if operation == "update" && target.Version == server.Inventory.AgentVersion {
		s.renderAdminError(w, r, http.StatusConflict, "이미 최신 Agent를 사용 중입니다", target.Version+" 버전이 현재 서버에서 확인되었습니다.")
		return
	}
	deploymentID, err := s.store.AssignAgentPackage(r.Context(), session.ScopeEnterpriseID(), serverID, target.ID, session.UserID)
	if err != nil {
		s.renderAdminError(w, r, http.StatusConflict, "Agent 작업을 예약할 수 없습니다", err.Error())
		return
	}
	s.audit(r, session.Username, "agent.package."+operation, serverID+":"+deploymentID+":"+target.ID, "success")
	action := map[string]string{"update": "업데이트", "rollback": "롤백"}[operation]
	http.Redirect(w, r, "/servers/"+serverID+"?tab=packages&notice="+url.QueryEscape("Agent "+action+"가 예약되었습니다. 다음 mTLS polling에서 적용하며 웹서버 모듈과 정책은 변경하지 않습니다."), http.StatusSeeOther)
}

func (s *Server) installServerModule(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		s.renderAdminError(w, r, http.StatusForbidden, "보안 정보가 만료되었습니다", "화면을 새로고침한 뒤 다시 시도하세요.")
		return
	}
	if s.catalog == nil {
		s.renderAdminError(w, r, http.StatusServiceUnavailable, "설치 파일을 사용할 수 없습니다", "Manager에 서명된 배포 bundle이 포함되어 있는지 확인하세요.")
		return
	}
	if r.FormValue("confirm") != "confirmed" {
		s.renderAdminError(w, r, http.StatusBadRequest, "설치 영향 확인이 필요합니다", "설치 유형과 웹서버를 확인한 뒤 다시 시도하세요.")
		return
	}
	session := sessionFrom(r)
	serverID := r.PathValue("id")
	server, err := s.store.ServerByID(r.Context(), session.ScopeEnterpriseID(), serverID)
	if err != nil || server.Revoked {
		s.renderAdminError(w, r, http.StatusNotFound, "서버를 찾을 수 없습니다", "등록 해제되었거나 현재 기업 범위에서 접근할 수 없는 서버입니다.")
		return
	}
	if !agentPackageManagementReady(server.Inventory) {
		s.renderAdminError(w, r, http.StatusConflict, "Agent 전환이 먼저 필요합니다", "기존 등록 정보를 유지한 채 자기 업데이트 지원 Agent로 전환한 뒤 모듈 설치를 진행하세요.")
		return
	}
	webServer := strings.TrimSpace(r.FormValue("web_server"))
	buildHash := strings.TrimSpace(r.FormValue("web_server_build"))
	installType := strings.TrimSpace(r.FormValue("install_type"))
	controlMode := model.NormalizeWebServerControl(strings.TrimSpace(r.FormValue("web_server_control")))
	if controlMode != model.WebServerControlStandard && controlMode != model.WebServerControlHooks {
		s.renderAdminError(w, r, http.StatusBadRequest, "웹서버 적용 방식이 올바르지 않습니다", "자동 설정 검사·재적용 또는 사용자 지정 실행 파일을 선택하세요.")
		return
	}
	candidate, ok := installationCandidate(server.Inventory, webServer, buildHash)
	if !ok {
		s.renderAdminError(w, r, http.StatusConflict, "웹서버 점검 정보가 변경되었습니다", "Agent의 다음 점검을 기다린 뒤 새로고침하여 다시 선택하세요.")
		return
	}
	inventory := server.Inventory
	inventory.WebServer = candidate.Kind
	inventory.WebServerVersion = candidate.Version
	inventory.WebServerBuild = candidate.BuildHash
	switch installType {
	case model.InstallationModePackage:
		if !candidate.PackageManaged {
			s.renderAdminError(w, r, http.StatusUnprocessableEntity, "패키지 설치를 선택할 수 없습니다", "배포판 패키지가 아닌 웹서버는 커스텀 ZIP 설치를 선택하세요.")
			return
		}
		inventory.IntegrationMode = model.IntegrationModeDistro
		inventory.InstallationMode = model.InstallationModePackage
	case model.InstallationModeCustomZIP:
		if candidate.BuildHash == "" {
			s.renderAdminError(w, r, http.StatusUnprocessableEntity, "웹서버 빌드 식별값이 필요합니다", "커스텀 ZIP은 현재 웹서버 빌드와 정확히 일치하는 경우에만 설치할 수 있습니다.")
			return
		}
		inventory.IntegrationMode = model.IntegrationModeExternal
		inventory.InstallationMode = model.InstallationModeCustomZIP
	default:
		s.renderAdminError(w, r, http.StatusBadRequest, "설치 유형이 올바르지 않습니다", "패키지 기반 또는 커스텀 ZIP을 선택하세요.")
		return
	}
	agentPackage, modulePackage, err := s.catalog.Resolve(inventory)
	if err != nil {
		s.renderAdminError(w, r, http.StatusUnprocessableEntity, "호환 설치 파일을 찾을 수 없습니다", err.Error())
		return
	}
	deploymentID, err := s.store.AssignPackagesWithControl(r.Context(), session.ScopeEnterpriseID(), serverID, agentPackage.ID, modulePackage.ID, session.UserID, controlMode)
	if err != nil {
		s.renderAdminError(w, r, http.StatusConflict, "설치를 예약할 수 없습니다", err.Error())
		return
	}
	s.audit(r, session.Username, "server.install."+installType, serverID+":"+deploymentID+":"+candidate.Kind+":"+controlMode, "success")
	http.Redirect(w, r, "/servers/"+serverID+"?tab=packages&notice="+url.QueryEscape("Agent가 선택한 설치 파일을 내려받아 검증·설치합니다. 기존 설정 파일은 수정하지 않으며 정책 적용 시 선택한 방식으로 설정 검사와 재적용을 수행합니다."), http.StatusSeeOther)
}

func installationCandidate(inventory model.Inventory, webServer, buildHash string) (model.WebServerCandidate, bool) {
	candidates := inventory.WebServerCandidates
	if len(candidates) == 0 && inventory.WebServer != "" {
		candidates = []model.WebServerCandidate{{Kind: inventory.WebServer, Version: inventory.WebServerVersion, BuildHash: inventory.WebServerBuild, PackageManaged: model.NormalizeIntegrationMode(inventory.IntegrationMode) == model.IntegrationModeDistro}}
	}
	for _, candidate := range candidates {
		if candidate.Kind == webServer && candidate.BuildHash == buildHash {
			return candidate, true
		}
	}
	return model.WebServerCandidate{}, false
}

func agentPackageManagementReady(inventory model.Inventory) bool {
	return model.HasCapability(inventory.Capabilities, model.AgentCapabilitySelfUpdate) && model.HasCapability(inventory.Capabilities, model.AgentCapabilityLocalRollback)
}

func (s *Server) revokeServer(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		s.renderAdminError(w, r, http.StatusForbidden, "보안 정보가 만료되었습니다", "화면을 새로고침한 뒤 다시 시도하세요.")
		return
	}
	if r.FormValue("confirm") != "confirmed" {
		s.renderServers(w, r, http.StatusBadRequest, "서버 등록 해제 내용을 확인해야 합니다.")
		return
	}
	session := sessionFrom(r)
	serverID := r.PathValue("id")
	server, err := s.store.ServerByID(r.Context(), session.ScopeEnterpriseID(), serverID)
	if err != nil {
		s.renderServers(w, r, http.StatusNotFound, "서버를 찾을 수 없거나 이미 등록 해제되었습니다.")
		return
	}
	if !validServerRevokeConfirmation(server.Name, r.FormValue("server_name_confirm")) {
		s.renderAdminError(w, r, http.StatusBadRequest, "서버 이름이 일치하지 않습니다", "등록 해제할 서버 이름을 화면에 표시된 값과 동일하게 입력하세요.")
		return
	}
	if err := s.store.RevokeServer(r.Context(), session.ScopeEnterpriseID(), serverID, session.UserID); err != nil {
		s.renderServers(w, r, http.StatusNotFound, "서버를 찾을 수 없거나 이미 등록 해제되었습니다.")
		return
	}
	s.audit(r, session.Username, "server.revoke", serverID, "success")
	http.Redirect(w, r, "/servers?notice="+url.QueryEscape("서버 등록을 해제하고 Agent 인증서를 차단했습니다."), http.StatusSeeOther)
}

func (s *Server) deleteRevokedServer(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		s.renderAdminError(w, r, http.StatusForbidden, "보안 정보가 만료되었습니다", "화면을 새로고침한 뒤 다시 시도하세요.")
		return
	}
	if r.FormValue("confirm") != "confirmed" {
		s.renderAdminError(w, r, http.StatusBadRequest, "영구 삭제 내용을 확인해야 합니다", "삭제되는 서버 정보와 운영 이력을 확인하세요.")
		return
	}
	session := sessionFrom(r)
	serverID := r.PathValue("id")
	server, err := s.store.ServerByID(r.Context(), session.ScopeEnterpriseID(), serverID)
	if err != nil {
		s.renderAdminError(w, r, http.StatusNotFound, "서버를 찾을 수 없습니다", "이미 삭제되었거나 현재 기업 범위에서 접근할 수 없는 서버입니다.")
		return
	}
	if !server.Revoked {
		s.renderAdminError(w, r, http.StatusConflict, "등록 해제된 서버만 영구 삭제할 수 있습니다", "먼저 위험 작업에서 서버 등록을 해제하세요.")
		return
	}
	if !validServerRevokeConfirmation(server.Name, r.FormValue("server_name_confirm")) {
		s.renderAdminError(w, r, http.StatusBadRequest, "서버 이름이 일치하지 않습니다", "영구 삭제할 서버 이름을 화면에 표시된 값과 동일하게 입력하세요.")
		return
	}
	if err := s.store.DeleteRevokedServer(r.Context(), session.ScopeEnterpriseID(), serverID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.renderAdminError(w, r, http.StatusConflict, "서버를 영구 삭제할 수 없습니다", "등록 해제 상태와 현재 기업 범위를 다시 확인하세요.")
			return
		}
		s.renderAdminError(w, r, http.StatusInternalServerError, "서버를 영구 삭제할 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	s.audit(r, session.Username, "server.delete", serverID+":"+server.Name, "success")
	http.Redirect(w, r, "/servers?notice="+url.QueryEscape("등록 해제된 서버와 연결된 운영 이력을 영구 삭제했습니다."), http.StatusSeeOther)
}
