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
	s.renderGroups(w, r, http.StatusOK, "", strings.TrimSpace(r.URL.Query().Get("edit")), "", nil, "")
}

func (s *Server) renderGroups(w http.ResponseWriter, r *http.Request, status int, pageError, formGroupID, formName string, formServerIDs []string, formEnterpriseID string) {
	session := sessionFrom(r)
	groups, err := s.store.ListGroups(r.Context(), session.ScopeEnterpriseID())
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "서버 그룹을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	servers, err := s.store.ListServers(r.Context(), session.ScopeEnterpriseID(), 500)
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "서버 목록을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	views := make([]groupView, 0, len(groups))
	formSelected := make(map[string]bool, len(formServerIDs))
	for _, id := range formServerIDs {
		formSelected[id] = true
	}
	for _, group := range groups {
		selected := make(map[string]bool, len(group.Members))
		for _, member := range group.Members {
			selected[member.ID] = true
		}
		choices := make([]groupServerChoice, 0)
		for _, server := range servers {
			if server.EnterpriseID == group.EnterpriseID && !server.Revoked {
				isSelected := selected[server.ID]
				if formGroupID == group.ID && pageError != "" {
					isSelected = formSelected[server.ID]
				}
				choices = append(choices, groupServerChoice{Server: server, Selected: isSelected})
			}
		}
		if formGroupID == group.ID && pageError != "" {
			group.Name = formName
		}
		views = append(views, groupView{Group: group, Servers: choices})
	}
	createChoices := make([]groupServerChoice, 0, len(servers))
	for _, server := range servers {
		if !server.Revoked {
			createChoices = append(createChoices, groupServerChoice{Server: server, Selected: formGroupID == "" && formSelected[server.ID]})
		}
	}
	filterQuery := strings.TrimSpace(r.URL.Query().Get("q"))
	filterEnterprise := strings.TrimSpace(r.URL.Query().Get("enterprise_id"))
	query := strings.ToLower(filterQuery)
	filteredViews := views[:0]
	for _, view := range views {
		if query != "" && !strings.Contains(strings.ToLower(view.Group.Name), query) && !strings.Contains(strings.ToLower(view.Group.EnterpriseName), query) {
			continue
		}
		if session.IsSystemAdmin() && filterEnterprise != "" && view.Group.EnterpriseID != filterEnterprise {
			continue
		}
		filteredViews = append(filteredViews, view)
	}
	data := map[string]any{
		"Groups":             filteredViews,
		"GroupTotal":         len(views),
		"CreateServers":      createChoices,
		"Error":              pageError,
		"FormName":           formName,
		"FormEnterpriseID":   formEnterpriseID,
		"EditGroupID":        formGroupID,
		"FilterQuery":        filterQuery,
		"FilterEnterpriseID": filterEnterprise,
		"CreateOpen":         r.URL.Query().Get("create") == "1" || (r.Method == http.MethodPost && r.URL.Path == "/groups" && pageError != ""),
	}
	if session.IsSystemAdmin() {
		enterprises, err := s.store.ListEnterprises(r.Context())
		if err != nil {
			s.renderAdminError(w, r, http.StatusInternalServerError, "기업 목록을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
			return
		}
		data["Enterprises"] = enterprises
	}
	data["Notice"] = strings.TrimSpace(r.URL.Query().Get("notice"))
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
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
		s.renderAdminError(w, r, http.StatusForbidden, "보안 정보가 만료되었습니다", "화면을 새로고침한 뒤 다시 시도하세요.")
		return
	}
	session := sessionFrom(r)
	name := truncate(strings.TrimSpace(r.FormValue("name")), 255)
	enterpriseID, ok := s.enterpriseIDForSession(r.Context(), session, strings.TrimSpace(r.FormValue("enterprise_id")))
	if !ok {
		s.renderGroups(w, r, http.StatusBadRequest, "활성 기업을 선택하세요.", groupID, name, r.Form["server_ids"], strings.TrimSpace(r.FormValue("enterprise_id")))
		return
	}
	serverIDs := r.Form["server_ids"]
	savedID, err := s.store.SaveGroup(r.Context(), session.ScopeEnterpriseID(), groupID, enterpriseID, name, session.UserID, serverIDs)
	if err != nil {
		s.renderGroups(w, r, http.StatusBadRequest, "서버 그룹을 저장할 수 없습니다: "+err.Error(), groupID, name, serverIDs, enterpriseID)
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
		s.renderAdminError(w, r, http.StatusForbidden, "보안 정보가 만료되었습니다", "화면을 새로고침한 뒤 다시 시도하세요.")
		return
	}
	if r.FormValue("confirm") != "confirmed" {
		s.renderGroups(w, r, http.StatusBadRequest, "서버 그룹 삭제 내용을 확인해야 합니다.", "", "", nil, "")
		return
	}
	groupID := r.PathValue("id")
	session := sessionFrom(r)
	if err := s.store.DeleteGroup(r.Context(), session.ScopeEnterpriseID(), groupID); err != nil {
		s.renderGroups(w, r, http.StatusNotFound, "서버 그룹을 찾을 수 없거나 이미 삭제되었습니다.", "", "", nil, "")
		return
	}
	s.audit(r, session.Username, "group.delete", groupID, "success")
	http.Redirect(w, r, "/groups?notice="+url.QueryEscape("서버 그룹이 삭제되었습니다."), http.StatusSeeOther)
}
