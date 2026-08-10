package manager

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	defaultInstallTokenDays = 30
	maxInstallTokenDays     = 90
	maxInstallTokenUses     = 10_000
)

func (s *Server) renderEnrollment(w http.ResponseWriter, r *http.Request, extra map[string]any) {
	w.Header().Set("Cache-Control", "no-store")
	session := sessionFrom(r)
	requestedEnterpriseID := strings.TrimSpace(r.URL.Query().Get("enterprise_id"))
	if value, exists := extra["FormEnterpriseID"]; exists {
		if formEnterpriseID, ok := value.(string); ok && strings.TrimSpace(formEnterpriseID) != "" {
			requestedEnterpriseID = strings.TrimSpace(formEnterpriseID)
		}
	}
	selectedEnterpriseID, selected := s.enterpriseIDForSession(r.Context(), session, requestedEnterpriseID)
	if !selected && requestedEnterpriseID != "" {
		selectedEnterpriseID, selected = s.enterpriseIDForSession(r.Context(), session, "")
	}
	selectedEnterpriseName := session.EnterpriseName
	installerSHA256, err := bootstrapInstallerSHA256()
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "설치 명령을 준비할 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	data := map[string]any{
		"AgentURL":                 s.cfg.PublicURL,
		"BootstrapTLSPin":          s.bootstrapTLSPin,
		"BootstrapInstallerSHA256": installerSHA256,
		"FormEnterpriseID":         selectedEnterpriseID,
		"SelectedEnterpriseID":     selectedEnterpriseID,
	}
	if session.IsSystemAdmin() {
		enterprises, err := s.store.ListEnterprises(r.Context())
		if err != nil {
			s.renderAdminError(w, r, http.StatusInternalServerError, "기업 목록을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
			return
		}
		data["Enterprises"] = enterprises
		for _, enterprise := range enterprises {
			if enterprise.ID == selectedEnterpriseID {
				selectedEnterpriseName = enterprise.Name
				break
			}
		}
	}
	if selected {
		items, err := s.store.ListEnterpriseInstallTokens(r.Context(), selectedEnterpriseID, 200)
		if err != nil {
			s.renderAdminError(w, r, http.StatusInternalServerError, "기업 설치 토큰을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
			return
		}
		if r.Method == http.MethodGet && activeEnterpriseInstallToken(items) == nil {
			session := sessionFrom(r)
			record, token, created, err := s.store.EnsurePersistentEnterpriseInstallToken(r.Context(), selectedEnterpriseID, "기업 설치 토큰", session.UserID)
			if err != nil {
				s.renderAdminError(w, r, http.StatusInternalServerError, "기업 설치 토큰을 준비할 수 없습니다", "잠시 후 화면을 새로고침해 다시 시도하세요.")
				return
			}
			if created {
				s.audit(r, session.Username, "enterprise_install_token.create", record.ID, "success")
				data["InstallToken"] = token
				data["InstallTokenRecord"] = record
			}
			items = append([]EnterpriseInstallTokenRecord{record}, items...)
		}
		data["InstallTokens"] = items
		if active := activeEnterpriseInstallToken(items); active != nil {
			data["ActiveInstallToken"] = active
		}
	}
	data["SelectedEnterpriseName"] = selectedEnterpriseName
	data["ScopeLabel"] = selectedEnterpriseName
	if !selected {
		data["Error"] = "설치 작업에 사용할 활성 기업 범위를 찾을 수 없습니다."
	}
	if _, created := data["InstallToken"]; created {
		switch {
		case r.URL.Query().Get("enterprise_created") == "1":
			data["Notice"] = "기업과 설치 토큰을 생성했습니다. 토큰 원문을 안전하게 보관하세요."
		case r.URL.Query().Get("revoked") == "1":
			data["Notice"] = "기존 토큰의 신규 설치 권한을 폐기하고 새 설치 토큰을 생성했습니다. 기존 Agent의 탐지 로그 수신에는 영향을 주지 않습니다."
		default:
			data["Notice"] = "활성 설치 토큰이 없어 자동으로 생성했습니다."
		}
	} else if r.URL.Query().Get("enterprise_created") == "1" {
		data["Notice"] = "기업이 등록되었으며 활성 설치 토큰을 확인했습니다."
	} else if r.URL.Query().Get("revoked") == "1" {
		data["Notice"] = "기업 설치 토큰의 신규 설치 권한을 폐기했습니다. 이미 등록된 Agent의 탐지 로그 수신에는 영향을 주지 않습니다."
	}
	status := http.StatusOK
	for key, value := range extra {
		if key == "Status" {
			if code, ok := value.(int); ok {
				status = code
			}
			continue
		}
		data[key] = value
	}
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
	_ = s.templates.ExecuteTemplate(w, "enrollment.html", s.viewData(r, "enrollments", data))
}

func bootstrapInstallerSHA256() (string, error) {
	raw, err := bootstrapFiles.ReadFile("bootstrap-install.sh")
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func installTokenParameters(name, daysText, maxText string) (string, int, int, bool) {
	name = truncate(strings.TrimSpace(name), 255)
	days := defaultInstallTokenDays
	if strings.TrimSpace(daysText) != "" {
		parsed, err := strconv.Atoi(strings.TrimSpace(daysText))
		if err != nil {
			return "", 0, 0, false
		}
		days = parsed
	}
	maximum := 0
	if strings.TrimSpace(maxText) != "" {
		parsed, err := strconv.Atoi(strings.TrimSpace(maxText))
		if err != nil {
			return "", 0, 0, false
		}
		maximum = parsed
	}
	return name, days, maximum, name != "" && days >= 1 && days <= maxInstallTokenDays && maximum >= 0 && maximum <= maxInstallTokenUses
}

func activeEnterpriseInstallToken(items []EnterpriseInstallTokenRecord) *EnterpriseInstallTokenRecord {
	for index := range items {
		if items[index].Active() {
			return &items[index]
		}
	}
	return nil
}

func (s *Server) createInstallToken(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		s.renderAdminError(w, r, http.StatusForbidden, "보안 정보가 만료되었습니다", "화면을 새로고침한 뒤 다시 시도하세요.")
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderEnrollment(w, r, map[string]any{"Status": http.StatusBadRequest, "Error": "입력 내용을 읽을 수 없습니다. 다시 입력해 주세요."})
		return
	}
	enterpriseID, ok := s.requestEnterpriseID(r)
	if !ok {
		s.renderEnrollment(w, r, map[string]any{"Status": http.StatusBadRequest, "Error": "유효한 기업을 선택하세요.", "FormEnterpriseID": strings.TrimSpace(r.FormValue("enterprise_id"))})
		return
	}
	session := sessionFrom(r)
	record, token, created, err := s.store.EnsurePersistentEnterpriseInstallToken(r.Context(), enterpriseID, "기업 설치 토큰", session.UserID)
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "기업 설치 토큰을 만들 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	if !created {
		s.renderEnrollment(w, r, map[string]any{"Status": http.StatusConflict, "Error": "이 기업에는 이미 활성 설치 토큰이 있습니다. 저장한 토큰을 계속 사용하거나 기존 토큰을 폐기한 뒤 새로 생성하세요.", "FormEnterpriseID": enterpriseID})
		return
	}
	s.audit(r, session.Username, "enterprise_install_token.create", record.ID, "success")
	s.renderEnrollment(w, r, map[string]any{"InstallToken": token, "InstallTokenRecord": record, "FormEnterpriseID": enterpriseID})
}

func (s *Server) revokeInstallToken(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		s.renderAdminError(w, r, http.StatusForbidden, "보안 정보가 만료되었습니다", "화면을 새로고침한 뒤 다시 시도하세요.")
		return
	}
	if r.FormValue("confirm") != "confirmed" {
		s.renderEnrollment(w, r, map[string]any{"Status": http.StatusBadRequest, "Error": "기업 설치 토큰 폐기 내용을 확인해야 합니다.", "FormEnterpriseID": strings.TrimSpace(r.FormValue("enterprise_id"))})
		return
	}
	session := sessionFrom(r)
	enterpriseID, ok := s.enterpriseIDForSession(r.Context(), session, strings.TrimSpace(r.FormValue("enterprise_id")))
	if !ok {
		s.renderEnrollment(w, r, map[string]any{"Status": http.StatusBadRequest, "Error": "유효한 기업을 선택하세요.", "FormEnterpriseID": strings.TrimSpace(r.FormValue("enterprise_id"))})
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		s.renderAdminError(w, r, http.StatusNotFound, "설치 토큰을 찾을 수 없습니다", "이미 폐기되었거나 접근할 수 없는 토큰입니다.")
		return
	}
	if err := s.store.RevokeEnterpriseInstallToken(r.Context(), id, enterpriseID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.renderAdminError(w, r, http.StatusNotFound, "설치 토큰을 찾을 수 없습니다", "이미 폐기되었거나 접근할 수 없는 토큰입니다.")
			return
		}
		s.renderAdminError(w, r, http.StatusInternalServerError, "설치 토큰을 폐기할 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	s.audit(r, session.Username, "enterprise_install_token.revoke", id, "success")
	http.Redirect(w, r, "/enrollments/new?revoked=1&enterprise_id="+enterpriseID, http.StatusSeeOther)
}

func (s *Server) apiCreateInstallToken(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		writeProblem(w, http.StatusForbidden, "invalid csrf token")
		return
	}
	var request struct {
		EnterpriseID  string `json:"enterprise_id"`
		Name          string `json:"name"`
		ExpiresInDays int    `json:"expires_in_days"`
		MaxUses       int    `json:"max_enrollments"`
		Persistent    bool   `json:"persistent"`
	}
	if err := decodeJSON(w, r, &request, 16<<10); err != nil {
		return
	}
	enterpriseID, ok := s.enterpriseIDForSession(r.Context(), sessionFrom(r), strings.TrimSpace(request.EnterpriseID))
	if !ok {
		writeProblem(w, http.StatusBadRequest, "valid enterprise is required")
		return
	}
	name := truncate(strings.TrimSpace(request.Name), 255)
	expiresAt := persistentInstallTokenExpiry
	maximum := 0
	persistent := request.Persistent
	if persistent {
		if request.ExpiresInDays != 0 || request.MaxUses != 0 {
			writeProblem(w, http.StatusBadRequest, "persistent token cannot set expires_in_days or max_enrollments")
			return
		}
		if name == "" {
			writeProblem(w, http.StatusBadRequest, "name is required")
			return
		}
	} else {
		if request.ExpiresInDays == 0 {
			request.ExpiresInDays = 30
		}
		var valid bool
		name, request.ExpiresInDays, maximum, valid = installTokenParameters(request.Name, strconv.Itoa(request.ExpiresInDays), strconv.Itoa(request.MaxUses))
		if !valid {
			writeProblem(w, http.StatusBadRequest, "name, expiry days (1..90) and optional maximum enrollments (0..10000) are required")
			return
		}
		expiresAt = time.Now().UTC().Add(time.Duration(request.ExpiresInDays) * 24 * time.Hour)
	}
	session := sessionFrom(r)
	var record EnterpriseInstallTokenRecord
	var token string
	var err error
	if persistent {
		var created bool
		record, token, created, err = s.store.EnsurePersistentEnterpriseInstallToken(r.Context(), enterpriseID, name, session.UserID)
		if err == nil && !created {
			writeProblem(w, http.StatusConflict, "enterprise already has an active install token")
			return
		}
	} else {
		record, token, err = s.store.CreateEnterpriseInstallToken(r.Context(), enterpriseID, name, session.UserID, expiresAt, maximum)
	}
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "create enterprise install token")
		return
	}
	s.audit(r, session.Username, "enterprise_install_token.create", record.ID, "success")
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": record.ID, "token": token, "token_prefix": record.TokenPrefix, "expires_at": record.ExpiresAt,
		"max_enrollments": maximum, "persistent": persistent, "agent_api": s.cfg.PublicURL,
	})
}
