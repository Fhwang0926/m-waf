package manager

import (
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
	"web_control_standard": "표준 웹서버 제어 사용",
	"web_control_hooks":    "고객 Hook 사용",
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
	if command == "web_control_standard" || command == "web_control_hooks" {
		redirectPath = "/servers/" + serverID
	}
	http.Redirect(w, r, redirectPath+"?notice="+url.QueryEscape(label+" 명령이 예약되었습니다."), http.StatusSeeOther)
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
	http.Redirect(w, r, "/servers?notice="+url.QueryEscape("Agent와 WAF 모듈 "+map[string]string{"update": "업데이트", "rollback": "롤백"}[operation]+"가 예약되었습니다."), http.StatusSeeOther)
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
	webServer := strings.TrimSpace(r.FormValue("web_server"))
	buildHash := strings.TrimSpace(r.FormValue("web_server_build"))
	installType := strings.TrimSpace(r.FormValue("install_type"))
	controlMode := model.NormalizeWebServerControl(strings.TrimSpace(r.FormValue("web_server_control")))
	if controlMode != model.WebServerControlStandard && controlMode != model.WebServerControlHooks {
		s.renderAdminError(w, r, http.StatusBadRequest, "웹서버 제어 방식이 올바르지 않습니다", "표준 제어 또는 고객 Hook을 선택하세요.")
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
		if candidate.PackageManaged {
			s.renderAdminError(w, r, http.StatusUnprocessableEntity, "커스텀 ZIP 설치 대상이 아닙니다", "배포판 패키지 웹서버는 패키지 기반 설치를 선택하세요.")
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
	http.Redirect(w, r, "/servers/"+serverID+"?notice="+url.QueryEscape("Agent가 선택한 설치 파일을 내려받아 검증·설치합니다. 고객 설정 파일은 수정하지 않으며 정책 적용 시 선택한 방식으로 configtest와 reload를 수행합니다."), http.StatusSeeOther)
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
	if err := s.store.RevokeServer(r.Context(), session.ScopeEnterpriseID(), serverID, session.UserID); err != nil {
		s.renderServers(w, r, http.StatusNotFound, "서버를 찾을 수 없거나 이미 등록 해제되었습니다.")
		return
	}
	s.audit(r, session.Username, "server.revoke", serverID, "success")
	http.Redirect(w, r, "/servers?notice="+url.QueryEscape("서버 등록을 해제하고 Agent 인증서를 차단했습니다."), http.StatusSeeOther)
}
