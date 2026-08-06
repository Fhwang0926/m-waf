package manager

import (
	"net/http"
	"net/url"
	"strings"
)

type groupServerChoice struct {
	Server   ServerRecord
	Selected bool
}

type groupView struct {
	Group   GroupRecord
	Servers []groupServerChoice
}

func (s *Server) groups(w http.ResponseWriter, r *http.Request) {
	session := sessionFrom(r)
	groups, err := s.store.ListGroups(r.Context(), session.ScopeEnterpriseID())
	if err != nil {
		http.Error(w, "load server groups", http.StatusInternalServerError)
		return
	}
	servers, err := s.store.ListServers(r.Context(), session.ScopeEnterpriseID(), 500)
	if err != nil {
		http.Error(w, "load servers", http.StatusInternalServerError)
		return
	}
	views := make([]groupView, 0, len(groups))
	for _, group := range groups {
		selected := make(map[string]bool, len(group.Members))
		for _, member := range group.Members {
			selected[member.ID] = true
		}
		choices := make([]groupServerChoice, 0)
		for _, server := range servers {
			if server.EnterpriseID == group.EnterpriseID && !server.Revoked {
				choices = append(choices, groupServerChoice{Server: server, Selected: selected[server.ID]})
			}
		}
		views = append(views, groupView{Group: group, Servers: choices})
	}
	data := map[string]any{"Groups": views, "Servers": servers}
	if session.IsSystemAdmin() {
		enterprises, err := s.store.ListEnterprises(r.Context())
		if err != nil {
			http.Error(w, "load enterprises", http.StatusInternalServerError)
			return
		}
		data["Enterprises"] = enterprises
	}
	data["Notice"] = strings.TrimSpace(r.URL.Query().Get("notice"))
	_ = s.templates.ExecuteTemplate(w, "groups.html", s.viewData(r, "groups", data))
}

func (s *Server) createGroup(w http.ResponseWriter, r *http.Request) {
	s.saveGroup(w, r, "")
}

func (s *Server) updateGroup(w http.ResponseWriter, r *http.Request) {
	s.saveGroup(w, r, r.PathValue("id"))
}

func (s *Server) saveGroup(w http.ResponseWriter, r *http.Request, groupID string) {
	if !s.validCSRF(r) {
		http.Error(w, "invalid csrf token", http.StatusForbidden)
		return
	}
	session := sessionFrom(r)
	name := truncate(strings.TrimSpace(r.FormValue("name")), 255)
	enterpriseID := strings.TrimSpace(r.FormValue("enterprise_id"))
	serverIDs := r.Form["server_ids"]
	savedID, err := s.store.SaveGroup(r.Context(), session.ScopeEnterpriseID(), groupID, enterpriseID, name, session.UserID, serverIDs)
	if err != nil {
		http.Error(w, "서버 그룹을 저장할 수 없습니다: "+err.Error(), http.StatusBadRequest)
		return
	}
	action := "group.create"
	if groupID != "" {
		action = "group.update"
	}
	s.audit(r, session.Username, action, savedID, "success")
	http.Redirect(w, r, "/groups?notice="+url.QueryEscape("서버 그룹이 저장되었습니다."), http.StatusSeeOther)
}

func (s *Server) deleteGroup(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		http.Error(w, "invalid csrf token", http.StatusForbidden)
		return
	}
	groupID := r.PathValue("id")
	session := sessionFrom(r)
	if err := s.store.DeleteGroup(r.Context(), session.ScopeEnterpriseID(), groupID); err != nil {
		http.Error(w, "server group not found", http.StatusNotFound)
		return
	}
	s.audit(r, session.Username, "group.delete", groupID, "success")
	http.Redirect(w, r, "/groups?notice="+url.QueryEscape("서버 그룹이 삭제되었습니다."), http.StatusSeeOther)
}
