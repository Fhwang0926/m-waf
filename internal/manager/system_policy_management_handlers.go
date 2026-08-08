package manager

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/Fhwang0926/m-waf/internal/systempolicy"
)

func (s *Server) systemPolicyTemplate(ctx context.Context, reference string) (systempolicy.Template, bool) {
	item, err := s.store.SystemPolicyTemplateByID(ctx, strings.TrimSpace(reference))
	if err == nil {
		return item, true
	}
	return splitSystemPolicyReference(s.policyCatalog, reference)
}

func (s *Server) latestSystemPolicyTemplate(ctx context.Context, key string) (systempolicy.Template, bool) {
	item, err := s.store.LatestSystemPolicyTemplate(ctx, strings.TrimSpace(key))
	if err == nil {
		return item, true
	}
	return systempolicy.Template{}, false
}

func (s *Server) defaultSystemPolicyTemplate(ctx context.Context) systempolicy.Template {
	if item, ok := s.latestSystemPolicyTemplate(ctx, systempolicy.DefaultTemplateKey); ok {
		return item
	}
	// The former channel-specific baselines remain usable only as the migration
	// base when a canonical crs-baseline has not been published yet.
	if item, ok := s.latestSystemPolicyTemplate(ctx, systempolicy.DefaultOperatingTemplateKey); ok {
		return item
	}
	if item, ok := s.latestSystemPolicyTemplate(ctx, systempolicy.DefaultStableTemplateKey); ok {
		return item
	}
	return systempolicy.Template{}
}

func (s *Server) publishedSystemPolicyTemplates(ctx context.Context) ([]systempolicy.Template, error) {
	item := s.defaultSystemPolicyTemplate(ctx)
	if item.Key != "" {
		return []systempolicy.Template{item}, nil
	}
	_, err := s.store.ListPublishedSystemPolicyTemplates(ctx)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	return []systempolicy.Template{}, nil
}

func (s *Server) newSystemPolicyVersion(w http.ResponseWriter, r *http.Request) {
	destination := "/system-policies/migrations/new"
	if base := strings.TrimSpace(r.URL.Query().Get("base")); base != "" {
		destination += "?base=" + url.QueryEscape(base)
	}
	http.Redirect(w, r, destination, http.StatusSeeOther)
}

func (s *Server) publishSystemPolicyVersion(w http.ResponseWriter, r *http.Request) {
	s.renderAdminError(w, r, http.StatusGone, "직접 시스템 정책 게시는 종료되었습니다", "검증된 CRS 소스를 선택해 새 정책 버전을 만들고 검증한 뒤 게시하세요.")
}

func (s *Server) withdrawSystemPolicyVersion(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		s.renderAdminError(w, r, http.StatusForbidden, "보안 정보가 만료되었습니다", "화면을 새로고침한 뒤 다시 시도하세요.")
		return
	}
	if r.FormValue("confirm") != "withdraw" {
		http.Redirect(w, r, "/system-policies?notice="+url.QueryEscape("회수 확인이 필요합니다."), http.StatusSeeOther)
		return
	}
	id := truncate(strings.TrimSpace(r.PathValue("id")), 255)
	if err := s.store.WithdrawSystemPolicyVersion(r.Context(), id); err != nil {
		http.Redirect(w, r, "/system-policies?notice="+url.QueryEscape("기업 정책이 사용 중이거나 현재 게시본인 버전은 회수할 수 없습니다."), http.StatusSeeOther)
		return
	}
	session := sessionFrom(r)
	s.audit(r, session.Username, "system_policy.withdraw", id, "success")
	http.Redirect(w, r, "/system-policies?notice="+url.QueryEscape("시스템 정책 버전을 회수했습니다."), http.StatusSeeOther)
}

func nextSystemPolicyVersion(current string) string {
	parts := strings.Split(current, ".")
	if len(parts) != 3 {
		return "1.0.0"
	}
	patch, err := strconv.Atoi(parts[2])
	if err != nil {
		return "1.0.0"
	}
	return parts[0] + "." + parts[1] + "." + strconv.Itoa(patch+1)
}

func newerSystemPolicyVersion(candidate, current string) bool {
	left := strings.Split(candidate, ".")
	right := strings.Split(current, ".")
	if len(left) != 3 || len(right) != 3 {
		return false
	}
	for index := 0; index < 3; index++ {
		candidatePart, candidateErr := strconv.Atoi(left[index])
		currentPart, currentErr := strconv.Atoi(right[index])
		if candidateErr != nil || currentErr != nil {
			return false
		}
		if candidatePart != currentPart {
			return candidatePart > currentPart
		}
	}
	return false
}
