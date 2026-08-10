package manager

import (
	"net/http"
	"net/url"
	"strings"
)

func (s *Server) legacyGroupsRedirect(w http.ResponseWriter, r *http.Request) {
	target := "/policies"
	if enterpriseID := strings.TrimSpace(r.URL.Query().Get("enterprise_id")); enterpriseID != "" {
		target += "?enterprise_id=" + url.QueryEscape(enterpriseID)
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}
