package manager

import (
	"database/sql"
	"encoding/base64"
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
	items, err := s.store.ListEnterpriseInstallTokens(r.Context(), session.ScopeEnterpriseID(), 200)
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "기업 설치 토큰을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	data := map[string]any{
		"InstallTokens":   items,
		"AgentURL":        s.cfg.AgentPublicURL,
		"CABase64":        base64.StdEncoding.EncodeToString([]byte(s.ca.CertificatePEM())),
		"FormExpiresDays": strconv.Itoa(defaultInstallTokenDays),
	}
	if session.IsSystemAdmin() {
		enterprises, err := s.store.ListEnterprises(r.Context())
		if err != nil {
			s.renderAdminError(w, r, http.StatusInternalServerError, "기업 목록을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
			return
		}
		data["Enterprises"] = enterprises
	}
	if r.URL.Query().Get("revoked") == "1" {
		data["Notice"] = "기업 설치 토큰을 폐기했습니다. 이미 등록된 Agent의 mTLS 연결에는 영향을 주지 않습니다."
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

func (s *Server) createInstallToken(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		s.renderAdminError(w, r, http.StatusForbidden, "보안 정보가 만료되었습니다", "화면을 새로고침한 뒤 다시 시도하세요.")
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderEnrollment(w, r, map[string]any{"Status": http.StatusBadRequest, "Error": "입력 내용을 읽을 수 없습니다. 다시 입력해 주세요."})
		return
	}
	name, days, maximum, valid := installTokenParameters(r.FormValue("name"), r.FormValue("expires_in_days"), r.FormValue("max_enrollments"))
	if !valid {
		s.renderEnrollment(w, r, map[string]any{"Status": http.StatusBadRequest, "Error": "토큰 이름, 1~90일의 유효 기간과 선택적인 최대 등록 수를 확인하세요.", "FormEnterpriseID": strings.TrimSpace(r.FormValue("enterprise_id")), "FormTokenName": name, "FormExpiresDays": strings.TrimSpace(r.FormValue("expires_in_days")), "FormMaxEnrollments": strings.TrimSpace(r.FormValue("max_enrollments"))})
		return
	}
	enterpriseID, ok := s.requestEnterpriseID(r)
	if !ok {
		s.renderEnrollment(w, r, map[string]any{"Status": http.StatusBadRequest, "Error": "유효한 기업을 선택하세요.", "FormEnterpriseID": strings.TrimSpace(r.FormValue("enterprise_id")), "FormTokenName": name, "FormExpiresDays": strconv.Itoa(days), "FormMaxEnrollments": strings.TrimSpace(r.FormValue("max_enrollments"))})
		return
	}
	session := sessionFrom(r)
	record, token, err := s.store.CreateEnterpriseInstallToken(r.Context(), enterpriseID, name, session.UserID, time.Now().UTC().Add(time.Duration(days)*24*time.Hour), maximum)
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "기업 설치 토큰을 만들 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	s.audit(r, session.Username, "enterprise_install_token.create", record.ID, "success")
	s.renderEnrollment(w, r, map[string]any{"InstallToken": token, "InstallTokenRecord": record})
}

func (s *Server) revokeInstallToken(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		s.renderAdminError(w, r, http.StatusForbidden, "보안 정보가 만료되었습니다", "화면을 새로고침한 뒤 다시 시도하세요.")
		return
	}
	if r.FormValue("confirm") != "confirmed" {
		s.renderEnrollment(w, r, map[string]any{"Status": http.StatusBadRequest, "Error": "기업 설치 토큰 폐기 내용을 확인해야 합니다."})
		return
	}
	session := sessionFrom(r)
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		s.renderAdminError(w, r, http.StatusNotFound, "설치 토큰을 찾을 수 없습니다", "이미 폐기되었거나 접근할 수 없는 토큰입니다.")
		return
	}
	if err := s.store.RevokeEnterpriseInstallToken(r.Context(), id, session.ScopeEnterpriseID()); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.renderAdminError(w, r, http.StatusNotFound, "설치 토큰을 찾을 수 없습니다", "이미 폐기되었거나 접근할 수 없는 토큰입니다.")
			return
		}
		s.renderAdminError(w, r, http.StatusInternalServerError, "설치 토큰을 폐기할 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	s.audit(r, session.Username, "enterprise_install_token.revoke", id, "success")
	http.Redirect(w, r, "/enrollments/new?revoked=1", http.StatusSeeOther)
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
	}
	if err := decodeJSON(w, r, &request, 16<<10); err != nil {
		return
	}
	if request.ExpiresInDays == 0 {
		request.ExpiresInDays = defaultInstallTokenDays
	}
	name, days, maximum, valid := installTokenParameters(request.Name, strconv.Itoa(request.ExpiresInDays), strconv.Itoa(request.MaxUses))
	if !valid {
		writeProblem(w, http.StatusBadRequest, "name, expiry days (1..90) and optional maximum enrollments (0..10000) are required")
		return
	}
	enterpriseID, ok := s.enterpriseIDForSession(r.Context(), sessionFrom(r), strings.TrimSpace(request.EnterpriseID))
	if !ok {
		writeProblem(w, http.StatusBadRequest, "valid enterprise is required")
		return
	}
	session := sessionFrom(r)
	record, token, err := s.store.CreateEnterpriseInstallToken(r.Context(), enterpriseID, name, session.UserID, time.Now().UTC().Add(time.Duration(days)*24*time.Hour), maximum)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "create enterprise install token")
		return
	}
	s.audit(r, session.Username, "enterprise_install_token.create", record.ID, "success")
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": record.ID, "token": token, "token_prefix": record.TokenPrefix, "expires_at": record.ExpiresAt,
		"max_enrollments": request.MaxUses, "agent_api": s.cfg.AgentPublicURL,
	})
}
