package manager

import (
	"net/http"
)

func (s *Server) account(w http.ResponseWriter, r *http.Request) {
	_ = s.templates.ExecuteTemplate(w, "account.html", s.viewData(r, "account", nil))
}

func (s *Server) updateOwnPassword(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		http.Error(w, "invalid csrf token", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	session := sessionFrom(r)
	user, err := s.store.UserByID(r.Context(), session.UserID)
	if err != nil || !verifyPassword(r.FormValue("current_password"), user.PasswordHash) {
		s.renderAccountError(w, r, "현재 비밀번호가 올바르지 않습니다.")
		return
	}
	password := r.FormValue("password")
	if len([]rune(password)) < 12 || len([]rune(password)) > 256 || password != r.FormValue("password_confirm") {
		s.renderAccountError(w, r, "새 비밀번호는 12자 이상이어야 하며 확인 값과 같아야 합니다.")
		return
	}
	passwordHash, err := hashPassword(password)
	if err != nil {
		http.Error(w, "password change unavailable", http.StatusInternalServerError)
		return
	}
	if err := s.store.UpdateOwnPassword(r.Context(), session.UserID, passwordHash); err != nil {
		http.Error(w, "password change unavailable", http.StatusInternalServerError)
		return
	}
	s.audit(r, session.Username, "account.password_change", session.UserID, "success")
	clearSessionCookie(w)
	http.Redirect(w, r, "/login?password_changed=1", http.StatusSeeOther)
}

func (s *Server) renderAccountError(w http.ResponseWriter, r *http.Request, message string) {
	w.WriteHeader(http.StatusBadRequest)
	_ = s.templates.ExecuteTemplate(w, "account.html", s.viewData(r, "account", map[string]any{"Error": message}))
}
