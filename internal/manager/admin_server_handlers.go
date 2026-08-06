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
		http.Error(w, "invalid csrf token", http.StatusForbidden)
		return
	}
	command := strings.TrimSpace(r.FormValue("command"))
	label, ok := allowedAgentCommands[command]
	if !ok || r.FormValue("confirm") != "confirmed" {
		http.Error(w, "valid command and confirmation are required", http.StatusBadRequest)
		return
	}
	if (command == "agent_stop" || command == "server_stop") && r.FormValue("recovery_confirm") != "confirmed" {
		http.Error(w, "external recovery confirmation is required for stop commands", http.StatusBadRequest)
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
		http.Error(w, "명령을 예약할 수 없습니다: "+err.Error(), status)
		return
	}
	s.audit(r, session.Username, "server.command", serverID+":"+commandID+":"+command, "success")
	http.Redirect(w, r, "/servers?notice="+url.QueryEscape(label+" 명령이 예약되었습니다."), http.StatusSeeOther)
}

func (s *Server) deployServerPackages(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		http.Error(w, "invalid csrf token", http.StatusForbidden)
		return
	}
	if s.catalog == nil {
		http.Error(w, "package bundle unavailable", http.StatusServiceUnavailable)
		return
	}
	if r.FormValue("confirm") != "confirmed" {
		http.Error(w, "package deployment confirmation is required", http.StatusBadRequest)
		return
	}
	session := sessionFrom(r)
	serverID := r.PathValue("id")
	server, err := s.store.ServerByID(r.Context(), session.ScopeEnterpriseID(), serverID)
	if err != nil || server.Revoked {
		http.Error(w, "server not found", http.StatusNotFound)
		return
	}
	operation := strings.TrimSpace(r.FormValue("operation"))
	var agentID, moduleID string
	switch operation {
	case "update":
		agentPackage, modulePackage, resolveErr := s.catalog.Resolve(server.Inventory)
		if resolveErr != nil {
			http.Error(w, "업데이트 패키지를 찾을 수 없습니다: "+resolveErr.Error(), http.StatusUnprocessableEntity)
			return
		}
		agentID, moduleID = agentPackage.ID, modulePackage.ID
	case "rollback":
		currentAgent, currentModule, currentErr := s.store.CurrentPackageIDs(r.Context(), serverID)
		if currentErr != nil {
			http.Error(w, "현재 패키지를 확인할 수 없습니다.", http.StatusInternalServerError)
			return
		}
		agentPackage, modulePackage, rollbackErr := s.catalog.Rollback(currentAgent, currentModule)
		if rollbackErr != nil {
			http.Error(w, "롤백 패키지를 찾을 수 없습니다: "+rollbackErr.Error(), http.StatusUnprocessableEntity)
			return
		}
		agentID, moduleID = agentPackage.ID, modulePackage.ID
	default:
		http.Error(w, "operation must be update or rollback", http.StatusBadRequest)
		return
	}
	deploymentID, err := s.store.AssignPackages(r.Context(), session.ScopeEnterpriseID(), serverID, agentID, moduleID, session.UserID)
	if err != nil {
		http.Error(w, "패키지 배포를 예약할 수 없습니다: "+err.Error(), http.StatusConflict)
		return
	}
	s.audit(r, session.Username, "package."+operation, serverID+":"+deploymentID, "success")
	http.Redirect(w, r, "/servers?notice="+url.QueryEscape("Agent와 WAF 모듈 "+map[string]string{"update": "업데이트", "rollback": "롤백"}[operation]+"가 예약되었습니다."), http.StatusSeeOther)
}

func (s *Server) revokeServer(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		http.Error(w, "invalid csrf token", http.StatusForbidden)
		return
	}
	if r.FormValue("confirm") != "confirmed" {
		http.Error(w, "confirmation is required", http.StatusBadRequest)
		return
	}
	session := sessionFrom(r)
	serverID := r.PathValue("id")
	if err := s.store.RevokeServer(r.Context(), session.ScopeEnterpriseID(), serverID, session.UserID); err != nil {
		http.Error(w, "server not found", http.StatusNotFound)
		return
	}
	s.audit(r, session.Username, "server.revoke", serverID, "success")
	http.Redirect(w, r, "/servers?notice="+url.QueryEscape("서버 등록을 해제하고 Agent 인증서를 차단했습니다."), http.StatusSeeOther)
}
