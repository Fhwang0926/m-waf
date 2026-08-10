package manager

import "net/http"

func (s *Server) reports(w http.ResponseWriter, r *http.Request) {
	_ = s.templates.ExecuteTemplate(w, "reports.html", s.viewData(r, "reports", nil))
}
