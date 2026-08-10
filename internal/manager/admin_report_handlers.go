package manager

import (
	"net/http"
	"time"
)

func (s *Server) reports(w http.ResponseWriter, r *http.Request) {
	session := sessionFrom(r)
	enterpriseID, ok := s.effectiveEnterpriseFilter(r, r.URL.Query().Get("enterprise_id"))
	if !ok {
		s.renderAdminError(w, r, http.StatusBadRequest, "기업 필터가 올바르지 않습니다", "활성 기업을 다시 선택하세요.")
		return
	}
	overview, err := s.loadOverview(r.Context(), overviewFilterFromRequest(r, enterpriseID), time.Now().UTC())
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "관제 보고서를 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	servers, err := s.store.ListServers(r.Context(), enterpriseID, 500)
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "서버 현황을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	policies, err := s.store.ListEnterprisePolicies(r.Context(), enterpriseID, systemPolicyServerLimit)
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "보호 정책을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}

	filterPolicy := r.URL.Query().Get("policy_id")
	filterServer := r.URL.Query().Get("server_id")
	selectedPolicyName := "전체 보호 정책"
	selectedServerName := "전체 서버"
	for _, policy := range policies {
		if policy.ID == filterPolicy {
			selectedPolicyName = policy.Name
			break
		}
	}
	for _, server := range servers {
		if server.ID == filterServer {
			selectedServerName = server.Name
			break
		}
	}

	data := map[string]any{
		"Overview":           overview,
		"Servers":            servers,
		"Policies":           policies,
		"FilterEnterprise":   enterpriseID,
		"FilterPolicy":       filterPolicy,
		"FilterServer":       filterServer,
		"SelectedPolicyName": selectedPolicyName,
		"SelectedServerName": selectedServerName,
	}
	if session.IsSystemAdmin() {
		enterprises, enterpriseErr := s.store.ListEnterprises(r.Context())
		if enterpriseErr != nil {
			s.renderAdminError(w, r, http.StatusInternalServerError, "기업 목록을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
			return
		}
		data["Enterprises"] = enterprises
	}
	_ = s.templates.ExecuteTemplate(w, "reports.html", s.viewData(r, "reports", data))
}
