package manager

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (s *Server) setup(w http.ResponseWriter, r *http.Request) {
	hasUsers, err := s.store.HasAdminUsers(r.Context())
	if err != nil {
		http.Error(w, "load administrator configuration", http.StatusInternalServerError)
		return
	}
	if hasUsers {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodGet {
		s.renderSetup(w, r, http.StatusOK, "")
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if !s.sessions.validSetupCSRFRequest(r) {
		s.renderSetup(w, r, http.StatusForbidden, "설정 보안 정보가 만료되었거나 브라우저 쿠키가 차단되었습니다. 새 보안 정보로 갱신했습니다. 비밀번호를 다시 입력해 시도하세요. 인증서 경고가 계속 표시되면 M-WAF CA 인증서를 신뢰 저장소에 등록하세요.")
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	displayName := truncate(strings.TrimSpace(r.FormValue("display_name")), 255)
	password := r.FormValue("password")
	if !validUsername(username) || displayName == "" || len([]rune(password)) < 12 || len([]rune(password)) > 256 || password != r.FormValue("password_confirm") {
		s.renderSetup(w, r, http.StatusBadRequest, "사용자명, 표시 이름과 12자 이상의 동일한 비밀번호를 확인하세요.")
		return
	}
	passwordHash, err := hashPassword(password)
	if err != nil {
		http.Error(w, "setup unavailable", http.StatusInternalServerError)
		return
	}
	user, err := s.store.CreateInitialSystemAdmin(r.Context(), username, displayName, passwordHash)
	if err != nil {
		if errors.Is(err, ErrSetupComplete) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		s.renderSetup(w, r, http.StatusBadRequest, "시스템 관리자 생성에 실패했습니다. 사용자명 중복 여부를 확인하세요.")
		return
	}
	token, session, err := s.sessions.create(user)
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	clearSetupCSRFCookie(w)
	setSessionCookie(w, token, time.Unix(session.ExpiresAt, 0))
	s.audit(r, user.Username, "system_admin.setup", user.ID, "success")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) renderSetup(w http.ResponseWriter, r *http.Request, status int, message string) {
	w.Header().Set("Cache-Control", "no-store")
	token, err := s.sessions.setupCSRFForRequest(w, r)
	if err != nil {
		http.Error(w, "setup unavailable", http.StatusInternalServerError)
		return
	}
	data := map[string]any{"CSRF": token, "Error": message, "Username": "", "DisplayName": ""}
	if r.Method == http.MethodPost {
		data["Username"] = truncate(strings.TrimSpace(r.FormValue("username")), 128)
		data["DisplayName"] = truncate(strings.TrimSpace(r.FormValue("display_name")), 255)
	}
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
	_ = s.templates.ExecuteTemplate(w, "setup.html", data)
}

func (s *Server) enterprises(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListEnterprises(r.Context())
	if err != nil {
		http.Error(w, "load enterprises", http.StatusInternalServerError)
		return
	}
	data := map[string]any{"Enterprises": items}
	if r.URL.Query().Get("created") == "1" {
		data["Notice"] = "기업이 등록되었습니다. 사용자 관리에서 기업 관리자를 추가하세요."
	}
	_ = s.templates.ExecuteTemplate(w, "enterprises.html", s.viewData(r, "enterprises", data))
}

func (s *Server) createEnterprise(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		http.Error(w, "invalid csrf token", http.StatusForbidden)
		return
	}
	name := truncate(strings.TrimSpace(r.FormValue("name")), 255)
	if name == "" {
		http.Error(w, "enterprise name is required", http.StatusBadRequest)
		return
	}
	session := sessionFrom(r)
	item, err := s.store.CreateEnterprise(r.Context(), name, session.UserID)
	if err != nil {
		http.Error(w, "기업 생성에 실패했습니다. 같은 이름이 등록되어 있는지 확인하세요.", http.StatusConflict)
		return
	}
	s.audit(r, session.Username, "enterprise.create", item.ID, "success")
	http.Redirect(w, r, "/enterprises?created=1", http.StatusSeeOther)
}

func (s *Server) systemSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := s.store.LogRetentionSettings(r.Context(), DefaultLogRetentionSettings(s.cfg.EventRetention))
	if err != nil {
		http.Error(w, "load system settings", http.StatusInternalServerError)
		return
	}
	data := map[string]any{"Settings": settings, "CleanupInterval": s.cfg.CleanupInterval}
	if r.URL.Query().Get("saved") == "1" {
		data["Notice"] = "로그 보존 설정이 저장되었습니다. 다음 정리 주기부터 적용됩니다."
	}
	_ = s.templates.ExecuteTemplate(w, "settings.html", s.viewData(r, "settings", data))
}

func (s *Server) updateSystemSettings(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		http.Error(w, "invalid csrf token", http.StatusForbidden)
		return
	}
	eventDays, eventErr := strconv.Atoi(strings.TrimSpace(r.FormValue("event_retention_days")))
	auditDays, auditErr := strconv.Atoi(strings.TrimSpace(r.FormValue("audit_retention_days")))
	settings := LogRetentionSettings{EventDays: eventDays, AuditDays: auditDays}
	if eventErr != nil || auditErr != nil || !settings.Valid() {
		http.Error(w, "event retention must be 1..3650 days and audit retention must be 30..3650 days", http.StatusBadRequest)
		return
	}
	session := sessionFrom(r)
	if err := s.store.UpdateLogRetentionSettings(r.Context(), settings, session.UserID); err != nil {
		http.Error(w, "save system settings", http.StatusInternalServerError)
		return
	}
	s.audit(r, session.Username, "system_settings.update", "log_retention", "success")
	http.Redirect(w, r, "/settings?saved=1", http.StatusSeeOther)
}

func (s *Server) users(w http.ResponseWriter, r *http.Request) {
	s.renderUsers(w, r, "")
}

func (s *Server) renderUsers(w http.ResponseWriter, r *http.Request, pageError string) {
	session := sessionFrom(r)
	items, err := s.store.ListUsers(r.Context(), session.ScopeEnterpriseID())
	if err != nil {
		http.Error(w, "load users", http.StatusInternalServerError)
		return
	}
	for i := range items {
		items[i].Manageable = sessionCanManageUser(session, items[i])
	}
	data := map[string]any{"Users": items, "Error": pageError}
	if session.IsSystemAdmin() {
		enterprises, err := s.store.ListEnterprises(r.Context())
		if err != nil {
			http.Error(w, "load enterprises", http.StatusInternalServerError)
			return
		}
		data["Enterprises"] = enterprises
	}
	if r.URL.Query().Get("created") == "1" {
		data["Notice"] = "사용자가 추가되었습니다."
	} else if r.URL.Query().Get("updated") == "1" {
		data["Notice"] = "사용자 정보가 수정되었습니다."
	} else if r.URL.Query().Get("deleted") == "1" {
		data["Notice"] = "사용자가 삭제 처리되었으며 로그인할 수 없습니다."
	}
	_ = s.templates.ExecuteTemplate(w, "users.html", s.viewData(r, "users", data))
}

func (s *Server) editUser(w http.ResponseWriter, r *http.Request) {
	session := sessionFrom(r)
	user, err := s.store.UserByID(r.Context(), r.PathValue("id"))
	if err != nil || !sessionCanManageUser(session, user) {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	_ = s.templates.ExecuteTemplate(w, "user-edit.html", s.viewData(r, "users", map[string]any{"User": user, "IsSelf": user.ID == session.UserID}))
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		http.Error(w, "invalid csrf token", http.StatusForbidden)
		return
	}
	session := sessionFrom(r)
	user, err := s.store.UserByID(r.Context(), r.PathValue("id"))
	if err != nil || !sessionCanManageUser(session, user) {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	displayName := truncate(strings.TrimSpace(r.FormValue("display_name")), 255)
	role := Role(strings.TrimSpace(r.FormValue("role")))
	active := r.FormValue("active") == "on"
	password := r.FormValue("password")
	passwordHash := ""
	if displayName == "" || !validEnterpriseRole(role) {
		http.Error(w, "표시 이름과 권한을 확인하세요.", http.StatusBadRequest)
		return
	}
	if user.ID == session.UserID && (role != RoleEnterpriseAdmin || !active) {
		http.Error(w, "자기 자신의 기업 관리자 권한이나 로그인 상태는 해제할 수 없습니다.", http.StatusConflict)
		return
	}
	if password != "" {
		if len([]rune(password)) < 12 || len([]rune(password)) > 256 || password != r.FormValue("password_confirm") {
			http.Error(w, "새 비밀번호는 12자 이상이며 확인 값과 같아야 합니다.", http.StatusBadRequest)
			return
		}
		passwordHash, err = hashPassword(password)
		if err != nil {
			http.Error(w, "password update unavailable", http.StatusInternalServerError)
			return
		}
	}
	if err := s.store.UpdateEnterpriseUser(r.Context(), user.EnterpriseID, user.ID, displayName, passwordHash, role, active); err != nil {
		if errors.Is(err, ErrLastEnterpriseAdmin) {
			http.Error(w, "기업에는 활성 기업 관리자가 한 명 이상 필요합니다.", http.StatusConflict)
			return
		}
		http.Error(w, "사용자를 수정할 수 없습니다.", http.StatusConflict)
		return
	}
	s.audit(r, session.Username, "user.update", user.ID+":"+string(role), "success")
	http.Redirect(w, r, "/users?updated=1", http.StatusSeeOther)
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		http.Error(w, "invalid csrf token", http.StatusForbidden)
		return
	}
	if r.FormValue("confirm") != "confirmed" {
		http.Error(w, "confirmation is required", http.StatusBadRequest)
		return
	}
	session := sessionFrom(r)
	user, err := s.store.UserByID(r.Context(), r.PathValue("id"))
	if err != nil || !sessionCanManageUser(session, user) {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	if user.ID == session.UserID {
		http.Error(w, "자기 자신의 기업 관리자 계정은 삭제할 수 없습니다.", http.StatusConflict)
		return
	}
	if err := s.store.DeleteEnterpriseUser(r.Context(), user.EnterpriseID, user.ID); err != nil {
		if errors.Is(err, ErrLastEnterpriseAdmin) {
			http.Error(w, "기업에는 활성 기업 관리자가 한 명 이상 필요합니다.", http.StatusConflict)
			return
		}
		http.Error(w, "사용자를 삭제할 수 없습니다.", http.StatusConflict)
		return
	}
	s.audit(r, session.Username, "user.delete", user.ID, "success")
	http.Redirect(w, r, "/users?deleted=1", http.StatusSeeOther)
}

func sessionCanManageUser(session sessionData, user UserRecord) bool {
	if !session.CanManageUsers() || user.Role == RoleSystemAdmin || user.EnterpriseID == "" {
		return false
	}
	if session.IsSystemAdmin() {
		return true
	}
	return session.EnterpriseID == user.EnterpriseID
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		http.Error(w, "invalid csrf token", http.StatusForbidden)
		return
	}
	session := sessionFrom(r)
	username := strings.TrimSpace(r.FormValue("username"))
	displayName := truncate(strings.TrimSpace(r.FormValue("display_name")), 255)
	password := r.FormValue("password")
	role := Role(strings.TrimSpace(r.FormValue("role")))
	enterpriseID := strings.TrimSpace(r.FormValue("enterprise_id"))
	if !session.IsSystemAdmin() {
		enterpriseID = session.EnterpriseID
	}
	if !validUsername(username) || displayName == "" || len([]rune(password)) < 12 || len([]rune(password)) > 256 || password != r.FormValue("password_confirm") || !validEnterpriseRole(role) {
		s.renderUsers(w, r, "사용자명, 표시 이름, 역할과 12자 이상의 동일한 비밀번호를 확인하세요.")
		return
	}
	if exists, err := s.store.EnterpriseExists(r.Context(), enterpriseID); err != nil || !exists {
		s.renderUsers(w, r, "유효한 기업을 선택하세요.")
		return
	}
	passwordHash, err := hashPassword(password)
	if err != nil {
		http.Error(w, "create user", http.StatusInternalServerError)
		return
	}
	user, err := s.store.CreateEnterpriseUser(r.Context(), enterpriseID, username, displayName, passwordHash, role, session.UserID)
	if err != nil {
		s.renderUsers(w, r, "사용자 생성에 실패했습니다. 같은 사용자명이 등록되어 있는지 확인하세요.")
		return
	}
	s.audit(r, session.Username, "user.create", user.ID+":"+string(user.Role), "success")
	http.Redirect(w, r, "/users?created=1", http.StatusSeeOther)
}

func (s *Server) viewData(r *http.Request, active string, values map[string]any) map[string]any {
	if values == nil {
		values = make(map[string]any)
	}
	session := sessionFrom(r)
	values["Active"] = active
	values["Session"] = session
	values["CSRF"] = session.CSRF
	values["IsSystemAdmin"] = session.IsSystemAdmin()
	values["CanOperate"] = session.CanOperate()
	values["CanManageUsers"] = session.CanManageUsers()
	return values
}

func (s *Server) requestEnterpriseID(r *http.Request) (string, bool) {
	return s.enterpriseIDForSession(r.Context(), sessionFrom(r), strings.TrimSpace(r.FormValue("enterprise_id")))
}

func (s *Server) enterpriseIDForSession(ctx context.Context, session sessionData, requested string) (string, bool) {
	if !session.IsSystemAdmin() {
		return session.EnterpriseID, session.EnterpriseID != ""
	}
	if requested == "" {
		return "", false
	}
	exists, err := s.store.EnterpriseExists(ctx, requested)
	return requested, err == nil && exists
}
