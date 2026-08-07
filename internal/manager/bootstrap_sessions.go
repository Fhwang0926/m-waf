package manager

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/Fhwang0926/m-waf/internal/model"
)

func (s *Server) createBootstrapSession(w http.ResponseWriter, r *http.Request) {
	installToken := bearerToken(r)
	if installToken == "" {
		writeProblem(w, http.StatusUnauthorized, "bearer enterprise install token required")
		return
	}
	limiterKey := fmt.Sprintf("%x", tokenHash(installToken))
	if !s.installLimiter.allow(limiterKey) {
		w.Header().Set("Retry-After", "60")
		s.audit(r, "bootstrap:"+installTokenPrefix(installToken), "enterprise_install_token.exchange", "rate_limit", "rejected")
		writeProblem(w, http.StatusTooManyRequests, "enterprise install token request limit exceeded")
		return
	}
	var request struct {
		Name      string          `json:"name"`
		Inventory model.Inventory `json:"inventory"`
	}
	if err := decodeJSON(w, r, &request, 64<<10); err != nil {
		return
	}
	label := truncate(strings.TrimSpace(request.Name), 255)
	if label == "" {
		label = truncate(strings.TrimSpace(request.Inventory.Hostname), 255)
	}
	if label == "" {
		writeProblem(w, http.StatusBadRequest, "server name or inventory hostname is required")
		return
	}
	if s.catalog == nil {
		writeProblem(w, http.StatusServiceUnavailable, "package bundle unavailable")
		return
	}
	if _, _, err := s.catalog.Resolve(request.Inventory); err != nil {
		writeProblem(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	token, expiresAt, err := s.store.ExchangeEnterpriseInstallToken(r.Context(), installToken, label, s.cfg.EnrollmentTTL)
	if err != nil {
		if errors.Is(err, ErrInvalidInstallToken) {
			s.audit(r, "bootstrap:"+installTokenPrefix(installToken), "enterprise_install_token.exchange", label, "rejected")
			writeProblem(w, http.StatusUnauthorized, "invalid enterprise install token")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "create bootstrap session")
		return
	}
	s.audit(r, "bootstrap:"+installTokenPrefix(installToken), "enterprise_install_token.exchange", label, "success")
	if strings.Contains(r.Header.Get("Accept"), "text/plain") {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprintln(w, token)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, map[string]any{"enrollment_token": token, "expires_at": expiresAt})
}
