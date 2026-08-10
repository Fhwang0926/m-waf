package manager

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Fhwang0926/m-waf/internal/model"
)

const (
	eventCursorBefore = "before"
	eventCursorAfter  = "after"
	auditLogPageSize  = 10
	overviewCacheTTL  = 15 * time.Second
	maxOverviewCache  = 128
)

type overviewCacheEntry struct {
	Data      OverviewData
	ExpiresAt time.Time
}

type eventPageResult struct {
	Items       []EventRecord
	HasPrevious bool
	HasNext     bool
}

type incidentPageResult struct {
	Items       []IncidentRecord
	HasPrevious bool
	HasNext     bool
}

type serverInstallationCandidateView struct {
	Kind               string
	Version            string
	BuildHash          string
	Binary             string
	PackageManaged     bool
	ConfigTestOK       bool
	PackageAvailable   bool
	CustomZIPAvailable bool
}

func (c serverInstallationCandidateView) Label() string {
	if c.Kind == "apache" {
		return "Apache HTTP Server"
	}
	if c.Kind == "nginx" {
		return "Nginx"
	}
	return c.Kind
}

type filterChip struct {
	Label     string
	RemoveURL string
}

func (s *Server) effectiveEnterpriseFilter(r *http.Request, requested string) (string, bool) {
	session := sessionFrom(r)
	scope := session.TenantScope()
	requested = scope.ReadEnterpriseID(requested)
	if !scope.GlobalAccess {
		return requested, requested != ""
	}
	requested = truncate(strings.TrimSpace(requested), 64)
	if requested == "" {
		return "", true
	}
	exists, err := s.store.EnterpriseExists(r.Context(), requested)
	return requested, err == nil && exists
}

func overviewFilterFromRequest(r *http.Request, enterpriseID string) OverviewFilter {
	return OverviewFilter{
		Range:        strings.TrimSpace(r.URL.Query().Get("range")),
		EnterpriseID: enterpriseID,
		PolicyID:     truncate(strings.TrimSpace(r.URL.Query().Get("policy_id")), 64),
		ServerID:     truncate(strings.TrimSpace(r.URL.Query().Get("server_id")), 64),
	}
}

func (s *Server) loadOverview(ctx context.Context, filter OverviewFilter, now time.Time) (OverviewData, error) {
	rangeKey, _, _, _ := normalizeOverviewRange(filter.Range, now)
	filter.Range = rangeKey
	cacheKey := strings.Join([]string{filter.Range, filter.EnterpriseID, filter.PolicyID, filter.ServerID}, "\x00")
	s.overviewCacheMu.Lock()
	if cached, ok := s.overviewCache[cacheKey]; ok && cached.ExpiresAt.After(now) {
		s.overviewCacheMu.Unlock()
		return cached.Data, nil
	}
	s.overviewCacheMu.Unlock()

	data, err := s.store.Overview(ctx, filter, now)
	if err != nil {
		return OverviewData{}, err
	}
	s.overviewCacheMu.Lock()
	for key, cached := range s.overviewCache {
		if !cached.ExpiresAt.After(now) {
			delete(s.overviewCache, key)
		}
	}
	if len(s.overviewCache) >= maxOverviewCache {
		clear(s.overviewCache)
	}
	s.overviewCache[cacheKey] = overviewCacheEntry{Data: data, ExpiresAt: now.Add(overviewCacheTTL)}
	s.overviewCacheMu.Unlock()
	return data, nil
}

func eventFilterFromRequest(r *http.Request, enterpriseID string) (EventFilter, string) {
	query := r.URL.Query()
	rangeKey, _, since, _ := normalizeOverviewRange(strings.TrimSpace(query.Get("range")), time.Now().UTC())
	serverID := query.Get("server_id")
	if serverID == "" {
		serverID = query.Get("server")
	}
	filter := EventFilter{
		EnterpriseID: enterpriseID,
		PolicyID:     truncate(strings.TrimSpace(query.Get("policy_id")), 64),
		ServerID:     truncate(strings.TrimSpace(serverID), 64),
		Severity:     strings.TrimSpace(query.Get("severity")),
		RuleID:       truncate(strings.TrimSpace(query.Get("rule_id")), 64),
		Query:        truncate(strings.TrimSpace(query.Get("q")), 255),
		Since:        since,
	}
	if at, id, direction, ok := decodeEventCursor(query.Get("cursor")); ok {
		filter.CursorAt = at
		filter.CursorID = id
		filter.CursorDirection = direction
	}
	if len(filter.Severity) != 1 || filter.Severity[0] < '0' || filter.Severity[0] > '7' {
		filter.Severity = ""
	}
	switch query.Get("result") {
	case "blocked":
		value := true
		filter.Blocked = &value
	case "detected":
		value := false
		filter.Blocked = &value
	}
	return filter, rangeKey
}

func encodeEventCursor(event EventRecord, direction string) string {
	if event.ID == 0 || event.OccurredAt.IsZero() || direction != eventCursorBefore && direction != eventCursorAfter {
		return ""
	}
	raw := direction + "." + strconv.FormatInt(event.OccurredAt.UTC().UnixMicro(), 10) + "." + strconv.FormatUint(event.ID, 10)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func decodeEventCursor(value string) (time.Time, uint64, string, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return time.Time{}, 0, "", false
	}
	parts := strings.Split(string(raw), ".")
	if len(parts) != 3 || parts[0] != eventCursorBefore && parts[0] != eventCursorAfter {
		return time.Time{}, 0, "", false
	}
	micros, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || micros <= 0 {
		return time.Time{}, 0, "", false
	}
	id, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil || id == 0 {
		return time.Time{}, 0, "", false
	}
	return time.UnixMicro(micros).UTC(), id, parts[0], true
}

func paginateEventRecords(items []EventRecord, pageSize, page int, direction string) eventPageResult {
	result := eventPageResult{Items: items}
	if direction == eventCursorAfter {
		result.HasPrevious = len(result.Items) > pageSize
		if result.HasPrevious {
			result.Items = result.Items[:pageSize]
		}
		for left, right := 0, len(result.Items)-1; left < right; left, right = left+1, right-1 {
			result.Items[left], result.Items[right] = result.Items[right], result.Items[left]
		}
		result.HasNext = len(result.Items) != 0
		return result
	}
	result.HasNext = len(result.Items) > pageSize
	if result.HasNext {
		result.Items = result.Items[:pageSize]
	}
	result.HasPrevious = direction == eventCursorBefore || page > 1
	return result
}

func eventPageURL(r *http.Request, page int, cursor string) string {
	query := r.URL.Query()
	query.Del("event")
	query.Del("incident")
	query.Set("page", strconv.Itoa(page))
	query.Set("cursor", cursor)
	return "/events?" + query.Encode()
}

func paginateIncidentRecords(items []IncidentRecord, pageSize, page int, direction string) incidentPageResult {
	result := incidentPageResult{Items: items}
	if direction == eventCursorAfter {
		result.HasPrevious = len(result.Items) > pageSize
		if result.HasPrevious {
			result.Items = result.Items[:pageSize]
		}
		for left, right := 0, len(result.Items)-1; left < right; left, right = left+1, right-1 {
			result.Items[left], result.Items[right] = result.Items[right], result.Items[left]
		}
		result.HasNext = len(result.Items) != 0
		return result
	}
	result.HasNext = len(result.Items) > pageSize
	if result.HasNext {
		result.Items = result.Items[:pageSize]
	}
	result.HasPrevious = direction == eventCursorBefore || page > 1
	return result
}

func encodeIncidentCursor(incident IncidentRecord, direction string) string {
	return encodeEventCursor(EventRecord{ID: incident.ID, OccurredAt: incident.OccurredAt}, direction)
}

func eventFilterChips(r *http.Request, session sessionData) []filterChip {
	labels := []struct {
		Key    string
		Prefix string
	}{
		{"range", "기간"},
		{"enterprise_id", "기업"}, {"policy_id", "보호 정책"}, {"server", "서버"}, {"server_id", "서버"},
		{"result", "처리"}, {"category", "공격 유형"}, {"severity", "위험도"}, {"rule_id", "Rule"}, {"q", "검색"},
	}
	chips := make([]filterChip, 0)
	seen := make(map[string]bool)
	for _, item := range labels {
		value := strings.TrimSpace(r.URL.Query().Get(item.Key))
		if value == "" || seen[item.Prefix] || item.Key == "enterprise_id" && !session.IsSystemAdmin() {
			continue
		}
		seen[item.Prefix] = true
		labelValue := value
		if item.Key == "enterprise_id" || item.Key == "policy_id" || item.Key == "server" || item.Key == "server_id" {
			labelValue = "지정됨"
		}
		if item.Key == "result" {
			if value == "blocked" {
				labelValue = "차단"
			} else if value == "detected" {
				labelValue = "탐지"
			}
		}
		if item.Key == "range" {
			switch value {
			case "1h":
				labelValue = "최근 1시간"
			case "7d":
				labelValue = "최근 7일"
			default:
				labelValue = "최근 24시간"
			}
		}
		if item.Key == "severity" {
			switch value {
			case "2":
				labelValue = "치명적"
			case "3":
				labelValue = "오류"
			case "4":
				labelValue = "주의"
			case "5":
				labelValue = "알림"
			case "6":
				labelValue = "정보"
			}
		}
		if item.Key == "category" {
			labelValue = attackCategoryLabel(value)
		}
		query := r.URL.Query()
		query.Del(item.Key)
		if item.Key == "server" {
			query.Del("server_id")
		}
		if item.Key == "server_id" {
			query.Del("server")
		}
		query.Del("page")
		query.Del("cursor")
		query.Del("event")
		query.Del("incident")
		chips = append(chips, filterChip{Label: item.Prefix + " · " + labelValue, RemoveURL: "/events?" + query.Encode()})
	}
	return chips
}

func (s *Server) apiOverview(w http.ResponseWriter, r *http.Request) {
	enterpriseID, ok := s.effectiveEnterpriseFilter(r, r.URL.Query().Get("enterprise_id"))
	if !ok {
		writeProblem(w, http.StatusBadRequest, "invalid enterprise filter")
		return
	}
	data, err := s.loadOverview(r.Context(), overviewFilterFromRequest(r, enterpriseID), time.Now().UTC())
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "load overview")
		return
	}
	writeJSON(w, http.StatusOK, data)
}

func (s *Server) apiIncidents(w http.ResponseWriter, r *http.Request) {
	enterpriseID, ok := s.effectiveEnterpriseFilter(r, r.URL.Query().Get("enterprise_id"))
	if !ok {
		writeProblem(w, http.StatusBadRequest, "invalid enterprise filter")
		return
	}
	eventFilter, _ := eventFilterFromRequest(r, enterpriseID)
	category := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("category")))
	if !validateIncidentCategory(category) {
		category = ""
	}
	filter := IncidentFilter{
		EnterpriseID: enterpriseID, PolicyID: eventFilter.PolicyID, ServerID: eventFilter.ServerID,
		Category: category, Severity: eventFilter.Severity, RuleID: eventFilter.RuleID, Query: eventFilter.Query,
		Blocked: eventFilter.Blocked, Since: eventFilter.Since,
	}
	items, err := s.store.ListIncidents(r.Context(), sessionFrom(r).ScopeEnterpriseID(), filter, 100)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "load incidents")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) apiEventDetail(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil || id == 0 {
		writeProblem(w, http.StatusBadRequest, "invalid event id")
		return
	}
	event, err := s.store.EventByID(r.Context(), sessionFrom(r).ScopeEnterpriseID(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeProblem(w, http.StatusNotFound, "event not found")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "load event")
		return
	}
	related, err := s.store.TransactionEvents(r.Context(), sessionFrom(r).ScopeEnterpriseID(), event)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "load transaction events")
		return
	}
	links := map[string]string{"server": "/servers/" + event.AgentID, "policy": policyDetailURL(event.PolicyID)}
	if event.PolicyID != "" {
		links["exception_review"] = "/policies/" + event.PolicyID + "/edit?exception_uri=" + url.QueryEscape(event.URI)
	}
	writeJSON(w, http.StatusOK, map[string]any{"event": event, "related_rules": related, "links": links})
}

func policyDetailURL(id string) string {
	if id == "" {
		return ""
	}
	return "/policies/" + id
}

func (s *Server) serverDetail(w http.ResponseWriter, r *http.Request) {
	session := sessionFrom(r)
	server, err := s.store.ServerByID(r.Context(), session.ScopeEnterpriseID(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.renderAdminError(w, r, http.StatusNotFound, "서버를 찾을 수 없습니다", "등록 해제되었거나 현재 기업 범위에서 접근할 수 없는 서버입니다.")
			return
		}
		s.renderAdminError(w, r, http.StatusInternalServerError, "서버 상세를 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	allServers, err := s.store.ListServers(r.Context(), server.EnterpriseID, 5000)
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "서버의 보호 정책 상태를 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	for _, item := range allServers {
		if item.ID == server.ID {
			server = item
			break
		}
	}
	if s.catalog != nil {
		_, _, rollbackErr := s.catalog.Rollback(server.AgentPackageID, server.ModulePackageID)
		server.CanRollbackPackages = rollbackErr == nil
	}
	commands, err := s.store.ListServerCommands(r.Context(), session.ScopeEnterpriseID(), server.ID, 50)
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "서버 제어 이력을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	policies, err := s.store.ListEnterprisePolicies(r.Context(), server.EnterpriseID, 5000)
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "적용 정책을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	assigned := make([]EnterprisePolicyRecord, 0)
	for _, policy := range policies {
		if policy.ID == server.EnterprisePolicyID {
			assigned = append(assigned, policy)
			break
		}
	}
	installationCandidates := make([]serverInstallationCandidateView, 0, len(server.Inventory.WebServerCandidates))
	candidates := server.Inventory.WebServerCandidates
	if len(candidates) == 0 && server.Inventory.WebServer != "" {
		candidates = []model.WebServerCandidate{{Kind: server.Inventory.WebServer, Version: server.Inventory.WebServerVersion, BuildHash: server.Inventory.WebServerBuild, PackageManaged: model.NormalizeIntegrationMode(server.Inventory.IntegrationMode) == model.IntegrationModeDistro}}
	}
	for _, candidate := range candidates {
		view := serverInstallationCandidateView{Kind: candidate.Kind, Version: candidate.Version, BuildHash: candidate.BuildHash, Binary: candidate.Binary, PackageManaged: candidate.PackageManaged, ConfigTestOK: candidate.ConfigTestOK}
		if s.catalog != nil {
			inventory := server.Inventory
			inventory.WebServer, inventory.WebServerVersion, inventory.WebServerBuild = candidate.Kind, candidate.Version, candidate.BuildHash
			if candidate.PackageManaged {
				inventory.IntegrationMode, inventory.InstallationMode = model.IntegrationModeDistro, model.InstallationModePackage
				_, _, resolveErr := s.catalog.Resolve(inventory)
				view.PackageAvailable = resolveErr == nil
			} else {
				inventory.IntegrationMode, inventory.InstallationMode = model.IntegrationModeExternal, model.InstallationModeCustomZIP
				_, _, resolveErr := s.catalog.Resolve(inventory)
				view.CustomZIPAvailable = resolveErr == nil
			}
		}
		installationCandidates = append(installationCandidates, view)
	}
	data := map[string]any{"Server": server, "Commands": commands, "Policies": assigned, "InstallationCandidates": installationCandidates, "Notice": r.URL.Query().Get("notice"), "ScopeLabel": server.EnterpriseName}
	_ = s.templates.ExecuteTemplate(w, "server-detail.html", s.viewData(r, "servers", data))
}

func (s *Server) auditLogs(w http.ResponseWriter, r *http.Request) {
	rangeKey := strings.TrimSpace(r.URL.Query().Get("range"))
	var since time.Time
	switch rangeKey {
	case "1h":
		since = time.Now().UTC().Add(-time.Hour)
	case "7d":
		since = time.Now().UTC().Add(-7 * 24 * time.Hour)
	case "30d":
		since = time.Now().UTC().Add(-30 * 24 * time.Hour)
	default:
		rangeKey = "24h"
		since = time.Now().UTC().Add(-24 * time.Hour)
	}
	page := queryPage(r)
	filter := AuditLogFilter{Actor: truncate(strings.TrimSpace(r.URL.Query().Get("actor")), 255), Action: truncate(strings.TrimSpace(r.URL.Query().Get("action")), 255), Result: truncate(strings.TrimSpace(r.URL.Query().Get("result")), 32), Since: since, Offset: (page - 1) * auditLogPageSize}
	items, err := s.store.ListAuditLogs(r.Context(), filter, auditLogPageSize+1)
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "감사 로그를 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	hasNext := len(items) > auditLogPageSize
	if hasNext {
		items = items[:auditLogPageSize]
	}
	data := map[string]any{"Logs": items, "Range": rangeKey, "FilterActor": filter.Actor, "FilterAction": filter.Action, "FilterResult": filter.Result, "Page": page, "HasNext": hasNext}
	query := r.URL.Query()
	query.Del("page")
	if page > 1 {
		query.Set("page", strconv.Itoa(page-1))
		data["PreviousURL"] = "/audit-logs?" + query.Encode()
	}
	if hasNext {
		query.Set("page", strconv.Itoa(page+1))
		data["NextURL"] = "/audit-logs?" + query.Encode()
	}
	_ = s.templates.ExecuteTemplate(w, "audit-logs.html", s.viewData(r, "audit-logs", data))
}

func queryPage(r *http.Request) int {
	page, err := strconv.Atoi(r.URL.Query().Get("page"))
	if err != nil || page < 1 {
		return 1
	}
	if page > 10000 {
		return 10000
	}
	return page
}
