package manager

import (
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

var allowedAgentCommands = map[string]string{
	"agent_restart":  "Agent 재시작",
	"agent_stop":     "Agent 중지",
	"server_restart": "서버 재시작",
	"server_stop":    "서버 종료",
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
	http.Redirect(w, r, "/servers?notice="+url.QueryEscape(label+" 명령이 예약되었습니다."), http.StatusSeeOther)
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
	deploymentID, err := s.store.AssignPackages(r.Context(), session.ScopeEnterpriseID(), serverID, agentID, moduleID, session.UserID)
	if err != nil {
		s.renderServers(w, r, http.StatusConflict, "패키지 배포를 예약할 수 없습니다: "+err.Error())
		return
	}
	s.audit(r, session.Username, "package."+operation, serverID+":"+deploymentID, "success")
	http.Redirect(w, r, "/servers?notice="+url.QueryEscape("Agent와 WAF 모듈 "+map[string]string{"update": "업데이트", "rollback": "롤백"}[operation]+"가 예약되었습니다."), http.StatusSeeOther)
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
