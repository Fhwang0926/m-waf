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
	session := sessionFrom(r)
	items, err := s.store.ListEnterpriseInstallTokens(r.Context(), session.ScopeEnterpriseID(), 200)
	if err != nil {
		http.Error(w, "load enterprise install tokens", http.StatusInternalServerError)
		return
	}
	data := map[string]any{
		"InstallTokens": items,
		"AgentURL":      s.cfg.AgentPublicURL,
		"CABase64":      base64.StdEncoding.EncodeToString([]byte(s.ca.CertificatePEM())),
	}
	if session.IsSystemAdmin() {
		enterprises, err := s.store.ListEnterprises(r.Context())
		if err != nil {
			http.Error(w, "load enterprises", http.StatusInternalServerError)
			return
		}
		data["Enterprises"] = enterprises
	}
	if r.URL.Query().Get("revoked") == "1" {
		data["Notice"] = "기업 설치 토큰을 폐기했습니다. 이미 등록된 Agent의 mTLS 연결에는 영향을 주지 않습니다."
	}
	for key, value := range extra {
		data[key] = value
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
		http.Error(w, "invalid csrf token", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	name, days, maximum, valid := installTokenParameters(r.FormValue("name"), r.FormValue("expires_in_days"), r.FormValue("max_enrollments"))
	if !valid {
		http.Error(w, "name, expiry days (1..90) and optional maximum enrollments (1..10000) are required", http.StatusBadRequest)
		return
	}
	enterpriseID, ok := s.requestEnterpriseID(r)
	if !ok {
		http.Error(w, "valid enterprise is required", http.StatusBadRequest)
		return
	}
	session := sessionFrom(r)
	record, token, err := s.store.CreateEnterpriseInstallToken(r.Context(), enterpriseID, name, session.UserID, time.Now().UTC().Add(time.Duration(days)*24*time.Hour), maximum)
	if err != nil {
		http.Error(w, "create enterprise install token", http.StatusInternalServerError)
		return
	}
	s.audit(r, session.Username, "enterprise_install_token.create", record.ID, "success")
	s.renderEnrollment(w, r, map[string]any{"InstallToken": token, "InstallTokenRecord": record})
}

func (s *Server) revokeInstallToken(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		http.Error(w, "invalid csrf token", http.StatusForbidden)
		return
	}
	session := sessionFrom(r)
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		http.Error(w, "install token not found", http.StatusNotFound)
		return
	}
	if err := s.store.RevokeEnterpriseInstallToken(r.Context(), id, session.ScopeEnterpriseID()); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "install token not found", http.StatusNotFound)
			return
		}
		http.Error(w, "revoke enterprise install token", http.StatusInternalServerError)
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
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": record.ID, "token": token, "token_prefix": record.TokenPrefix, "expires_at": record.ExpiresAt,
		"max_enrollments": request.MaxUses, "agent_api": s.cfg.AgentPublicURL,
	})
}
