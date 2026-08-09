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
)

func (s *Server) setup(w http.ResponseWriter, r *http.Request) {
	hasUsers, err := s.store.HasAdminUsers(r.Context())
	if err != nil {
		s.renderSetup(w, r, http.StatusInternalServerError, "시스템 관리자 설정 상태를 불러올 수 없습니다. 잠시 후 다시 시도하세요.")
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
		s.renderSetup(w, r, http.StatusBadRequest, "입력 내용을 읽을 수 없습니다. 다시 입력해 주세요.")
		return
	}
	if !s.sessions.validSetupCSRFRequest(r) {
		s.renderSetup(w, r, http.StatusForbidden, "설정 보안 정보가 만료되었거나 브라우저 쿠키가 차단되었습니다. 새 보안 정보로 갱신했으므로 비밀번호를 다시 입력해 시도하세요.")
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
		s.renderSetup(w, r, http.StatusInternalServerError, "시스템 관리자 비밀번호를 안전하게 처리할 수 없습니다. 잠시 후 다시 시도하세요.")
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
		s.renderLogin(w, r, http.StatusInternalServerError, "시스템 관리자는 생성되었지만 로그인 세션을 만들 수 없습니다. 로그인 화면에서 다시 시도하세요.", username)
		return
	}
	clearSetupCSRFCookie(w)
	setSessionCookie(w, token, time.Unix(session.ExpiresAt, 0))
	s.audit(r, user.Username, "system_admin.setup", user.ID, "success")
	s.TriggerPolicySync()
	http.Redirect(w, r, "/open-source-policies?setup=1", http.StatusSeeOther)
}

func (s *Server) renderSetup(w http.ResponseWriter, r *http.Request, status int, message string) {
	w.Header().Set("Cache-Control", "no-store")
	token, err := s.sessions.setupCSRFForRequest(w, r)
	if err != nil {
		s.renderLogin(w, r, http.StatusInternalServerError, "최초 설정 보안 정보를 만들 수 없습니다. 잠시 후 다시 시도하세요.", "")
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
	s.renderEnterprises(w, r, http.StatusOK, "", "")
}

func (s *Server) enterpriseDetail(w http.ResponseWriter, r *http.Request) {
	enterpriseID := strings.TrimSpace(r.PathValue("id"))
	enterprise, err := s.store.EnterpriseManagementByID(r.Context(), enterpriseID)
	if errors.Is(err, sql.ErrNoRows) {
		s.renderAdminError(w, r, http.StatusNotFound, "기업을 찾을 수 없습니다", "삭제되었거나 존재하지 않는 기업입니다.")
		return
	}
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "기업 상세를 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}

	users, err := s.store.ListUsers(r.Context(), enterpriseID)
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "소속 사용자를 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	session := sessionFrom(r)
	activeUserCount := 0
	for i := range users {
		users[i].Manageable = enterprise.Active() && sessionCanManageUser(session, users[i])
		if users[i].Active {
			activeUserCount++
		}
	}
	servers, err := s.store.ListServers(r.Context(), enterpriseID, 5000)
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "소속 서버를 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	policies, err := s.store.ListEnterprisePolicies(r.Context(), enterpriseID, 5000)
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "기업 정책을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	groups, err := s.store.ListGroups(r.Context(), enterpriseID)
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "서버 그룹을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}

	data := map[string]any{
		"Enterprise":         enterprise,
		"Users":              users,
		"ActiveUserCount":    activeUserCount,
		"Servers":            servers,
		"Policies":           policies,
		"Groups":             groups,
		"VisibleUserCount":   len(users),
		"HasDeletedUserData": enterprise.UserCount > uint64(len(users)),
		"Notice":             r.URL.Query().Get("notice"),
		"Error":              r.URL.Query().Get("error"),
	}
	_ = s.templates.ExecuteTemplate(w, "enterprise-detail.html", s.viewData(r, "enterprises", data))
}

func (s *Server) renderEnterprises(w http.ResponseWriter, r *http.Request, status int, pageError, formName string) {
	items, err := s.store.ListEnterpriseManagement(r.Context())
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "기업 목록을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	query := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	filterStatus := strings.TrimSpace(r.URL.Query().Get("status"))
	filtered := items[:0]
	for _, item := range items {
		if query != "" && !strings.Contains(strings.ToLower(item.Name), query) {
			continue
		}
		if filterStatus == "active" && !item.Active() {
			continue
		}
		if filterStatus == "terminated" && item.Active() {
			continue
		}
		filtered = append(filtered, item)
	}
	data := map[string]any{
		"Enterprises":     filtered,
		"EnterpriseTotal": len(items),
		"Error":           pageError,
		"FormName":        formName,
		"FilterQuery":     strings.TrimSpace(r.URL.Query().Get("q")),
		"FilterStatus":    filterStatus,
		"CreateOpen":      r.URL.Query().Get("create") == "1" || (r.Method == http.MethodPost && r.URL.Path == "/enterprises" && pageError != ""),
	}
	if r.URL.Query().Get("created") == "1" {
		data["Notice"] = "기업이 등록되었습니다. 사용자 관리에서 기업 관리자를 추가하세요."
	} else if r.URL.Query().Get("deleted") == "1" {
		data["Notice"] = "연결 데이터가 없는 기업을 삭제했습니다."
	} else if r.URL.Query().Get("terminated") == "1" {
		data["Notice"] = "기업 운영을 종료했습니다. 사용자·신규 등록·Agent 연결은 차단되고 기존 이력은 보존됩니다."
	}
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
	_ = s.templates.ExecuteTemplate(w, "enterprises.html", s.viewData(r, "enterprises", data))
}

func (s *Server) deleteEnterprise(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		s.renderAdminError(w, r, http.StatusForbidden, "보안 정보가 만료되었습니다", "화면을 새로고침한 뒤 다시 시도하세요.")
		return
	}
	enterpriseID := strings.TrimSpace(r.PathValue("id"))
	confirmName := strings.TrimSpace(r.FormValue("confirm_name"))
	if enterpriseID == "" || confirmName == "" {
		s.redirectEnterpriseDetailError(w, r, enterpriseID, "기업 삭제 또는 운영 종료를 위해 기업명을 정확히 입력하세요.")
		return
	}
	session := sessionFrom(r)
	result, err := s.store.DeleteOrTerminateEnterprise(r.Context(), enterpriseID, confirmName, session.UserID)
	if err != nil {
		message := "기업 삭제 또는 운영 종료를 처리할 수 없습니다."
		switch {
		case errors.Is(err, sql.ErrNoRows):
			message = "기업을 찾을 수 없습니다."
		case errors.Is(err, ErrEnterpriseNotActive):
			message = "이미 운영 종료된 기업입니다."
		case errors.Is(err, ErrEnterpriseConfirmation):
			message = "입력한 기업명이 일치하지 않습니다."
		case errors.Is(err, ErrSystemEnterpriseProtected):
			message = "시스템 관리자가 소속된 기업은 삭제하거나 운영 종료할 수 없습니다."
		}
		s.redirectEnterpriseDetailError(w, r, enterpriseID, message)
		return
	}
	if result == EnterpriseDeleted {
		s.audit(r, session.Username, "enterprise.delete", enterpriseID, "success")
		http.Redirect(w, r, "/enterprises?deleted=1", http.StatusSeeOther)
		return
	}
	s.audit(r, session.Username, "enterprise.terminate", enterpriseID, "success")
	http.Redirect(w, r, "/enterprises/"+url.PathEscape(enterpriseID)+"?notice="+url.QueryEscape("기업 운영을 종료했습니다. 사용자·신규 등록·Agent 연결은 차단되고 기존 이력은 보존됩니다."), http.StatusSeeOther)
}

func (s *Server) redirectEnterpriseDetailError(w http.ResponseWriter, r *http.Request, enterpriseID, message string) {
	if enterpriseID == "" {
		s.renderAdminError(w, r, http.StatusBadRequest, "기업 작업을 처리할 수 없습니다", message)
		return
	}
	http.Redirect(w, r, "/enterprises/"+url.PathEscape(enterpriseID)+"?error="+url.QueryEscape(message), http.StatusSeeOther)
}

func (s *Server) createEnterprise(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		s.renderAdminError(w, r, http.StatusForbidden, "보안 정보가 만료되었습니다", "화면을 새로고침한 뒤 다시 시도하세요.")
		return
	}
	name := truncate(strings.TrimSpace(r.FormValue("name")), 255)
	if name == "" {
		s.renderEnterprises(w, r, http.StatusBadRequest, "기업명을 입력하세요.", name)
		return
	}
	session := sessionFrom(r)
	item, err := s.store.CreateEnterprise(r.Context(), name, session.UserID)
	if err != nil {
		s.renderEnterprises(w, r, http.StatusConflict, "기업 생성에 실패했습니다. 같은 이름이 등록되어 있는지 확인하세요.", name)
		return
	}
	s.audit(r, session.Username, "enterprise.create", item.ID, "success")
	s.TriggerPolicySync()
	http.Redirect(w, r, "/enterprises/"+url.PathEscape(item.ID)+"/users?enterprise_created=1&create=1", http.StatusSeeOther)
}

func (s *Server) systemSettings(w http.ResponseWriter, r *http.Request) {
	s.renderSystemSettings(w, r, http.StatusOK, "", nil)
}

func (s *Server) renderSystemSettings(w http.ResponseWriter, r *http.Request, status int, pageError string, submitted *LogRetentionSettings) {
	settings, err := s.store.LogRetentionSettings(r.Context(), DefaultLogRetentionSettings(s.cfg.EventRetention))
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "시스템 설정을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	if submitted != nil {
		settings = *submitted
	}
	data := map[string]any{"Settings": settings, "CleanupInterval": s.cfg.CleanupInterval, "Error": pageError}
	if r.URL.Query().Get("saved") == "1" {
		data["Notice"] = "로그 보존 설정이 저장되었습니다. 다음 정리 주기부터 적용됩니다."
	}
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
	_ = s.templates.ExecuteTemplate(w, "settings.html", s.viewData(r, "settings", data))
}

func (s *Server) updateSystemSettings(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		s.renderAdminError(w, r, http.StatusForbidden, "보안 정보가 만료되었습니다", "화면을 새로고침한 뒤 다시 시도하세요.")
		return
	}
	eventDays, eventErr := strconv.Atoi(strings.TrimSpace(r.FormValue("event_retention_days")))
	auditDays, auditErr := strconv.Atoi(strings.TrimSpace(r.FormValue("audit_retention_days")))
	settings := LogRetentionSettings{EventDays: eventDays, AuditDays: auditDays}
	if eventErr != nil || auditErr != nil || !settings.Valid() {
		s.renderSystemSettings(w, r, http.StatusBadRequest, "WAF 이벤트는 1~3650일, 관리자 감사 로그는 30~3650일 범위로 입력하세요.", &settings)
		return
	}
	session := sessionFrom(r)
	if err := s.store.UpdateLogRetentionSettings(r.Context(), settings, session.UserID); err != nil {
		s.renderSystemSettings(w, r, http.StatusInternalServerError, "로그 보존 설정을 저장할 수 없습니다. 잠시 후 다시 시도하세요.", &settings)
		return
	}
	s.audit(r, session.Username, "system_settings.update", "log_retention", "success")
	http.Redirect(w, r, "/settings?saved=1", http.StatusSeeOther)
}

func (s *Server) users(w http.ResponseWriter, r *http.Request) {
	s.renderUsers(w, r, "")
}

func (s *Server) renderUsers(w http.ResponseWriter, r *http.Request, pageError string) {
	s.renderUsersWithForm(w, r, http.StatusOK, pageError, nil)
}

func (s *Server) renderUsersWithForm(w http.ResponseWriter, r *http.Request, status int, pageError string, form map[string]any) {
	if enterpriseID := strings.TrimSpace(r.PathValue("enterprise_id")); enterpriseID != "" {
		s.renderSystemEnterpriseUsers(w, r, status, pageError, form, enterpriseID)
		return
	}
	session := sessionFrom(r)
	items, err := s.store.ListUsers(r.Context(), session.ScopeEnterpriseID())
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "사용자 목록을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	for i := range items {
		items[i].Manageable = sessionCanManageUser(session, items[i])
	}
	filterQuery := strings.TrimSpace(r.URL.Query().Get("q"))
	filterEnterprise := strings.TrimSpace(r.URL.Query().Get("enterprise_id"))
	filterRole := strings.TrimSpace(r.URL.Query().Get("role"))
	filterStatus := strings.TrimSpace(r.URL.Query().Get("status"))
	query := strings.ToLower(filterQuery)
	enterpriseUsers := make([]UserRecord, 0, len(items))
	systemUsers := make([]UserRecord, 0, 1)
	totalEnterpriseUsers := 0
	for _, item := range items {
		if item.Role == RoleSystemAdmin || item.EnterpriseID == "" {
			systemUsers = append(systemUsers, item)
			continue
		}
		totalEnterpriseUsers++
		if query != "" && !strings.Contains(strings.ToLower(item.DisplayName), query) && !strings.Contains(strings.ToLower(item.Username), query) && !strings.Contains(strings.ToLower(item.EnterpriseName), query) {
			continue
		}
		if session.IsSystemAdmin() && filterEnterprise != "" && item.EnterpriseID != filterEnterprise {
			continue
		}
		if filterRole != "" && string(item.Role) != filterRole {
			continue
		}
		if filterStatus == "active" && !item.Active {
			continue
		}
		if filterStatus == "inactive" && item.Active {
			continue
		}
		enterpriseUsers = append(enterpriseUsers, item)
	}
	data := map[string]any{
		"Users":              enterpriseUsers,
		"SystemUsers":        systemUsers,
		"UserTotal":          totalEnterpriseUsers,
		"Error":              pageError,
		"FilterQuery":        filterQuery,
		"FilterEnterpriseID": filterEnterprise,
		"FilterRole":         filterRole,
		"FilterStatus":       filterStatus,
		"CreateOpen":         r.URL.Query().Get("create") == "1" || pageError != "",
		"FormEnterpriseID":   filterEnterprise,
	}
	for key, value := range form {
		data[key] = value
	}
	if session.IsSystemAdmin() {
		enterprises, err := s.store.ListEnterprises(r.Context())
		if err != nil {
			s.renderAdminError(w, r, http.StatusInternalServerError, "기업 목록을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
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
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
	_ = s.templates.ExecuteTemplate(w, "users.html", s.viewData(r, "users", data))
}

func (s *Server) renderSystemEnterpriseUsers(w http.ResponseWriter, r *http.Request, status int, pageError string, form map[string]any, enterpriseID string) {
	enterprise, err := s.store.EnterpriseManagementByID(r.Context(), enterpriseID)
	if errors.Is(err, sql.ErrNoRows) {
		s.renderAdminError(w, r, http.StatusNotFound, "기업을 찾을 수 없습니다", "삭제되었거나 존재하지 않는 기업입니다.")
		return
	}
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "기업 사용자 목록을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	items, err := s.store.ListUsers(r.Context(), enterpriseID)
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "기업 사용자 목록을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	filterQuery := strings.TrimSpace(r.URL.Query().Get("q"))
	filterRole := strings.TrimSpace(r.URL.Query().Get("role"))
	filterStatus := strings.TrimSpace(r.URL.Query().Get("status"))
	query := strings.ToLower(filterQuery)
	users := make([]UserRecord, 0, len(items))
	userTotal := 0
	for _, item := range items {
		if item.Role == RoleSystemAdmin || item.EnterpriseID == "" {
			continue
		}
		userTotal++
		if query != "" && !strings.Contains(strings.ToLower(item.DisplayName), query) && !strings.Contains(strings.ToLower(item.Username), query) {
			continue
		}
		if filterRole != "" && string(item.Role) != filterRole {
			continue
		}
		if filterStatus == "active" && !item.Active {
			continue
		}
		if filterStatus == "inactive" && item.Active {
			continue
		}
		item.Manageable = enterprise.Active() && sessionCanManageUser(sessionFrom(r), item)
		users = append(users, item)
	}
	baseURL := "/enterprises/" + url.PathEscape(enterpriseID) + "/users"
	data := map[string]any{
		"Enterprise": enterprise, "Users": users, "UserTotal": userTotal, "Error": pageError,
		"FilterQuery": filterQuery, "FilterRole": filterRole, "FilterStatus": filterStatus,
		"CreateOpen": r.URL.Query().Get("create") == "1" || pageError != "", "UserBaseURL": baseURL,
	}
	for key, value := range form {
		data[key] = value
	}
	if r.URL.Query().Get("created") == "1" {
		data["Notice"] = "기업 사용자가 추가되었습니다."
	} else if r.URL.Query().Get("enterprise_created") == "1" {
		data["Notice"] = "기업이 등록되었습니다. 첫 기업 관리자를 추가하세요."
	} else if r.URL.Query().Get("updated") == "1" {
		data["Notice"] = "기업 사용자 정보가 수정되었습니다."
	} else if r.URL.Query().Get("deleted") == "1" {
		data["Notice"] = "기업 사용자가 삭제 처리되었습니다."
	}
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
	_ = s.templates.ExecuteTemplate(w, "enterprise-users.html", s.viewData(r, "enterprises", data))
}

func userManagementEnterpriseID(r *http.Request, session sessionData) string {
	if enterpriseID := strings.TrimSpace(r.PathValue("enterprise_id")); enterpriseID != "" {
		return enterpriseID
	}
	return session.EnterpriseID
}

func userManagementUserID(r *http.Request) string {
	if userID := strings.TrimSpace(r.PathValue("user_id")); userID != "" {
		return userID
	}
	return strings.TrimSpace(r.PathValue("id"))
}

func userManagementBaseURL(r *http.Request, session sessionData) string {
	if enterpriseID := strings.TrimSpace(r.PathValue("enterprise_id")); enterpriseID != "" {
		return "/enterprises/" + url.PathEscape(enterpriseID) + "/users"
	}
	return "/users"
}

func (s *Server) editUser(w http.ResponseWriter, r *http.Request) {
	s.renderUserEdit(w, r, http.StatusOK, "", nil)
}

func (s *Server) renderUserEdit(w http.ResponseWriter, r *http.Request, status int, pageError string, form map[string]any) {
	session := sessionFrom(r)
	user, err := s.store.UserByID(r.Context(), userManagementUserID(r))
	enterpriseID := userManagementEnterpriseID(r, session)
	if err != nil || user.EnterpriseID != enterpriseID || !sessionCanManageUser(session, user) {
		s.renderAdminError(w, r, http.StatusNotFound, "사용자를 찾을 수 없습니다", "삭제되었거나 관리 권한이 없는 사용자입니다.")
		return
	}
	baseURL := userManagementBaseURL(r, session)
	data := map[string]any{"User": user, "IsSelf": user.ID == session.UserID, "Error": pageError, "FormDisplayName": user.DisplayName, "FormRole": string(user.Role), "FormActive": user.Active, "ScopeLabel": user.EnterpriseName, "UserBaseURL": baseURL, "UserActionURL": baseURL + "/" + url.PathEscape(user.ID)}
	for key, value := range form {
		data[key] = value
	}
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
	active := "users"
	if session.InSystemConsole() {
		active = "enterprises"
	}
	_ = s.templates.ExecuteTemplate(w, "user-edit.html", s.viewData(r, active, data))
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		s.renderAdminError(w, r, http.StatusForbidden, "보안 정보가 만료되었습니다", "화면을 새로고침한 뒤 다시 시도하세요.")
		return
	}
	session := sessionFrom(r)
	user, err := s.store.UserByID(r.Context(), userManagementUserID(r))
	enterpriseID := userManagementEnterpriseID(r, session)
	if err != nil || user.EnterpriseID != enterpriseID || !sessionCanManageUser(session, user) {
		s.renderAdminError(w, r, http.StatusNotFound, "사용자를 찾을 수 없습니다", "삭제되었거나 관리 권한이 없는 사용자입니다.")
		return
	}
	displayName := truncate(strings.TrimSpace(r.FormValue("display_name")), 255)
	role := Role(strings.TrimSpace(r.FormValue("role")))
	active := r.FormValue("active") == "on"
	password := r.FormValue("password")
	passwordHash := ""
	if displayName == "" || !validEnterpriseRole(role) {
		s.renderUserEdit(w, r, http.StatusBadRequest, "표시 이름과 권한을 확인하세요.", map[string]any{"FormDisplayName": displayName, "FormRole": string(role), "FormActive": active})
		return
	}
	if user.ID == session.UserID && (role != RoleEnterpriseAdmin || !active) {
		s.renderUserEdit(w, r, http.StatusConflict, "자기 자신의 기업 관리자 권한이나 로그인 상태는 해제할 수 없습니다.", map[string]any{"FormDisplayName": displayName, "FormRole": string(role), "FormActive": active})
		return
	}
	if password != "" {
		if len([]rune(password)) < 12 || len([]rune(password)) > 256 || password != r.FormValue("password_confirm") {
			s.renderUserEdit(w, r, http.StatusBadRequest, "새 비밀번호는 12자 이상이며 확인 값과 같아야 합니다.", map[string]any{"FormDisplayName": displayName, "FormRole": string(role), "FormActive": active})
			return
		}
		passwordHash, err = hashPassword(password)
		if err != nil {
			s.renderUserEdit(w, r, http.StatusInternalServerError, "비밀번호 변경을 처리할 수 없습니다.", map[string]any{"FormDisplayName": displayName, "FormRole": string(role), "FormActive": active})
			return
		}
	}
	if err := s.store.UpdateEnterpriseUser(r.Context(), user.EnterpriseID, user.ID, displayName, passwordHash, role, active); err != nil {
		if errors.Is(err, ErrLastEnterpriseAdmin) {
			s.renderUserEdit(w, r, http.StatusConflict, "기업에는 활성 기업 관리자가 한 명 이상 필요합니다.", map[string]any{"FormDisplayName": displayName, "FormRole": string(role), "FormActive": active})
			return
		}
		s.renderUserEdit(w, r, http.StatusConflict, "사용자를 수정할 수 없습니다.", map[string]any{"FormDisplayName": displayName, "FormRole": string(role), "FormActive": active})
		return
	}
	s.audit(r, session.Username, "user.update", user.ID+":"+string(role), "success")
	http.Redirect(w, r, userManagementBaseURL(r, session)+"?updated=1", http.StatusSeeOther)
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		s.renderAdminError(w, r, http.StatusForbidden, "보안 정보가 만료되었습니다", "화면을 새로고침한 뒤 다시 시도하세요.")
		return
	}
	if r.FormValue("confirm") != "confirmed" {
		s.renderUserEdit(w, r, http.StatusBadRequest, "사용자 삭제 내용을 확인해야 합니다.", nil)
		return
	}
	session := sessionFrom(r)
	user, err := s.store.UserByID(r.Context(), userManagementUserID(r))
	enterpriseID := userManagementEnterpriseID(r, session)
	if err != nil || user.EnterpriseID != enterpriseID || !sessionCanManageUser(session, user) {
		s.renderAdminError(w, r, http.StatusNotFound, "사용자를 찾을 수 없습니다", "삭제되었거나 관리 권한이 없는 사용자입니다.")
		return
	}
	if user.ID == session.UserID {
		s.renderUserEdit(w, r, http.StatusConflict, "자기 자신의 기업 관리자 계정은 삭제할 수 없습니다.", nil)
		return
	}
	if err := s.store.DeleteEnterpriseUser(r.Context(), user.EnterpriseID, user.ID); err != nil {
		if errors.Is(err, ErrLastEnterpriseAdmin) {
			s.renderUserEdit(w, r, http.StatusConflict, "기업에는 활성 기업 관리자가 한 명 이상 필요합니다.", nil)
			return
		}
		s.renderUserEdit(w, r, http.StatusConflict, "사용자를 삭제할 수 없습니다.", nil)
		return
	}
	s.audit(r, session.Username, "user.delete", user.ID, "success")
	http.Redirect(w, r, userManagementBaseURL(r, session)+"?deleted=1", http.StatusSeeOther)
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
		s.renderAdminError(w, r, http.StatusForbidden, "보안 정보가 만료되었습니다", "화면을 새로고침한 뒤 다시 시도하세요.")
		return
	}
	session := sessionFrom(r)
	username := strings.TrimSpace(r.FormValue("username"))
	displayName := truncate(strings.TrimSpace(r.FormValue("display_name")), 255)
	password := r.FormValue("password")
	role := Role(strings.TrimSpace(r.FormValue("role")))
	enterpriseID := userManagementEnterpriseID(r, session)
	if !validUsername(username) || displayName == "" || len([]rune(password)) < 12 || len([]rune(password)) > 256 || password != r.FormValue("password_confirm") || !validEnterpriseRole(role) {
		s.renderUsersWithForm(w, r, http.StatusBadRequest, "사용자명, 표시 이름, 역할과 12자 이상의 동일한 비밀번호를 확인하세요.", map[string]any{"FormEnterpriseID": enterpriseID, "FormRole": string(role), "FormUsername": username, "FormDisplayName": displayName})
		return
	}
	if exists, err := s.store.EnterpriseExists(r.Context(), enterpriseID); err != nil || !exists {
		s.renderUsersWithForm(w, r, http.StatusBadRequest, "유효한 기업을 선택하세요.", map[string]any{"FormEnterpriseID": enterpriseID, "FormRole": string(role), "FormUsername": username, "FormDisplayName": displayName})
		return
	}
	passwordHash, err := hashPassword(password)
	if err != nil {
		s.renderUsersWithForm(w, r, http.StatusInternalServerError, "사용자 비밀번호를 안전하게 처리할 수 없습니다. 잠시 후 다시 시도하세요.", map[string]any{"FormEnterpriseID": enterpriseID, "FormRole": string(role), "FormUsername": username, "FormDisplayName": displayName})
		return
	}
	user, err := s.store.CreateEnterpriseUser(r.Context(), enterpriseID, username, displayName, passwordHash, role, session.UserID)
	if err != nil {
		s.renderUsersWithForm(w, r, http.StatusConflict, "사용자 생성에 실패했습니다. 같은 사용자명이 등록되어 있는지 확인하세요.", map[string]any{"FormEnterpriseID": enterpriseID, "FormRole": string(role), "FormUsername": username, "FormDisplayName": displayName})
		return
	}
	s.audit(r, session.Username, "user.create", user.ID+":"+string(user.Role), "success")
	http.Redirect(w, r, userManagementBaseURL(r, session)+"?created=1", http.StatusSeeOther)
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
	values["CanAccessSystemManagement"] = session.CanAccessSystemManagement()
	values["InSystemConsole"] = session.InSystemConsole()
	values["CanOperate"] = session.CanOperate()
	values["CanManageUsers"] = session.CanManageUsers()
	values["AccountURL"] = "/account"
	values["AccountPasswordURL"] = "/account/password"
	if session.InSystemConsole() {
		values["AccountURL"] = "/account?area=system"
		values["AccountPasswordURL"] = "/account/password?area=system"
	}
	if _, exists := values["ScopeLabel"]; !exists {
		if session.InSystemConsole() {
			values["ScopeLabel"] = "전체 기업"
			filterEnterprise, _ := values["FilterEnterprise"].(string)
			if filterEnterprise == "" {
				filterEnterprise, _ = values["FilterEnterpriseID"].(string)
			}
			if enterprises, ok := values["Enterprises"].([]EnterpriseRecord); ok {
				for _, enterprise := range enterprises {
					if enterprise.ID == filterEnterprise {
						values["ScopeLabel"] = enterprise.Name
						break
					}
				}
			}
		} else {
			values["ScopeLabel"] = session.EnterpriseName
		}
	}
	values["BundleReady"] = s.catalog != nil
	values["BundleVersion"] = ""
	values["BundleStatusLabel"] = "Manager 연결됨 · Bundle 확인 필요"
	values["BundleStatusCompact"] = "확인"
	values["BundleStatusTitle"] = "Manager는 연결되었지만 서명된 package bundle을 사용할 수 없습니다."
	if s.catalog != nil {
		bundleVersion := s.catalog.Manifest().BundleVersion
		values["BundleVersion"] = bundleVersion
		values["BundleStatusLabel"] = "Manager 연결됨 · Bundle " + bundleVersion
		values["BundleStatusCompact"] = "정상"
		values["BundleStatusTitle"] = "Manager와 서명된 package bundle을 사용할 수 있습니다."
	}
	values["DevLiveReload"] = s.cfg.DevLiveReload
	if s.cfg.DevLiveReload {
		values["DevInstanceID"] = s.instanceID
	}
	return values
}

func (s *Server) requestEnterpriseID(r *http.Request) (string, bool) {
	return s.enterpriseIDForSession(r.Context(), sessionFrom(r), strings.TrimSpace(r.FormValue("enterprise_id")))
}

func (s *Server) enterpriseIDForSession(ctx context.Context, session sessionData, requested string) (string, bool) {
	requested = session.TenantScope().MutationEnterpriseID(requested)
	exists, err := s.store.EnterpriseExists(ctx, requested)
	return requested, err == nil && exists
}
