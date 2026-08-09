package manager

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Fhwang0926/m-waf/internal/config"
	"github.com/Fhwang0926/m-waf/internal/localtime"
	"github.com/Fhwang0926/m-waf/internal/model"
	"github.com/Fhwang0926/m-waf/internal/packages"
	"github.com/Fhwang0926/m-waf/internal/protocol"
	"github.com/Fhwang0926/m-waf/internal/systempolicy"
	"github.com/Fhwang0926/m-waf/internal/version"
	webassets "github.com/Fhwang0926/m-waf/web"
)

//go:embed bootstrap-install.sh
var bootstrapFiles embed.FS

type contextKey string

const (
	contextSession contextKey = "session"
	contextAgentID contextKey = "agent_id"
)

type Server struct {
	cfg              config.Manager
	instanceID       string
	store            *Store
	catalog          *packages.Catalog
	catalogErr       error
	ca               *CertificateAuthority
	policySigner     *PolicySigner
	policyCatalog    *systempolicy.Catalog
	templates        *template.Template
	sessions         *sessionManager
	loginLimiter     *loginLimiter
	bootstrapLimiter *requestLimiter
	installLimiter   *requestLimiter
	downloadLimiter  *requestLimiter
	policySyncMu     sync.Mutex
	policySyncSignal chan struct{}
	overviewCacheMu  sync.Mutex
	overviewCache    map[string]overviewCacheEntry
	sourceMu         sync.RWMutex
	sourceSyncMu     sync.Mutex
	runtimeSources   map[string]runtimePolicySource
	lastCRSSync      time.Time
	geoIP            *geoIPResolver
	logger           *slog.Logger
}

func NewServer(cfg config.Manager, store *Store, logger *slog.Logger) (*Server, error) {
	ca, err := LoadCertificateAuthority(cfg.AgentCACertificate, cfg.AgentCAPrivateKey)
	if err != nil {
		return nil, err
	}
	policySigner, err := LoadPolicySigner(cfg.PolicySigningKey, cfg.PolicySigningPublic)
	if err != nil {
		return nil, err
	}
	policyCatalog, err := systempolicy.Load()
	if err != nil {
		return nil, err
	}
	templates, err := webassets.ParseTemplates()
	if err != nil {
		return nil, err
	}
	catalog, catalogErr := packages.Load(cfg.BundleRoot, cfg.BundlePublicKey, version.Commit, cfg.BundleAllowUnsigned)
	geoIP, geoErr := openGeoIPDatabase(cfg.GeoIPDatabase)
	if geoErr != nil {
		logger.Warn("geoip_database_unavailable", "path", cfg.GeoIPDatabase, "error", geoErr)
		geoIP = &geoIPResolver{}
	}
	server := &Server{
		cfg: cfg, instanceID: randomID(), store: store, catalog: catalog, catalogErr: catalogErr, ca: ca, policySigner: policySigner, policyCatalog: policyCatalog, templates: templates,
		sessions: newSessionManager(cfg.SessionKey), loginLimiter: newLoginLimiter(),
		bootstrapLimiter: newRequestLimiter(60, time.Minute), installLimiter: newRequestLimiter(60, time.Minute), downloadLimiter: newRequestLimiter(8, time.Minute), logger: logger,
		policySyncSignal: make(chan struct{}, 1), overviewCache: make(map[string]overviewCacheEntry), runtimeSources: make(map[string]runtimePolicySource), geoIP: geoIP,
	}
	if err := server.loadRuntimePolicySources(); err != nil {
		_ = geoIP.Close()
		return nil, fmt.Errorf("load Manager CRS sources: %w", err)
	}
	return server, nil
}

func (s *Server) Close() error { return s.geoIP.Close() }

func (s *Server) TriggerPolicySync() {
	select {
	case s.policySyncSignal <- struct{}{}:
	default:
	}
}

func (s *Server) PolicySyncSignal() <-chan struct{} { return s.policySyncSignal }

func (s *Server) SyncCatalog(ctx context.Context) error {
	if s.catalog == nil {
		if s.cfg.BundleRequired {
			return s.catalogErr
		}
		return nil
	}
	if err := s.store.SyncCatalog(ctx, s.catalog); err != nil {
		return err
	}
	return s.syncBundlePolicySources(ctx)
}

func (s *Server) live(w http.ResponseWriter, _ *http.Request) {
	payload := map[string]any{"status": "live", "version": version.Version, "commit": version.Commit}
	if s.cfg.DevLiveReload {
		payload["instance_id"] = s.instanceID
	}
	writeJSON(w, http.StatusOK, payload)
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		writeProblem(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	if s.cfg.BundleRequired && s.catalog == nil {
		writeProblem(w, http.StatusServiceUnavailable, "package bundle unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		hasUsers, err := s.store.HasAdminUsers(r.Context())
		if err != nil {
			s.renderLogin(w, r, http.StatusInternalServerError, "로그인 설정을 불러올 수 없습니다. 잠시 후 다시 시도하세요.", "")
			return
		}
		if !hasUsers {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}
		s.renderLogin(w, r, http.StatusOK, "", "")
		return
	}
	remote := remoteIP(r)
	if !s.loginLimiter.allow(remote) {
		s.renderLogin(w, r, http.StatusTooManyRequests, "로그인 시도가 너무 많습니다. 잠시 후 다시 시도하세요.", "")
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderLogin(w, r, http.StatusBadRequest, "입력 내용을 읽을 수 없습니다. 다시 입력해 주세요.", "")
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	user, err := s.store.UserByUsername(r.Context(), username)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		s.renderLogin(w, r, http.StatusInternalServerError, "로그인을 처리할 수 없습니다. 잠시 후 다시 시도하세요.", username)
		return
	}
	if err != nil || !user.Active || !verifyPassword(r.FormValue("password"), user.PasswordHash) {
		s.loginLimiter.fail(remote)
		s.renderLogin(w, r, http.StatusUnauthorized, "로그인 정보가 올바르지 않습니다.", username)
		return
	}
	s.loginLimiter.reset(remote)
	token, data, err := s.sessions.create(user)
	if err != nil {
		s.renderLogin(w, r, http.StatusInternalServerError, "로그인 세션을 만들 수 없습니다. 잠시 후 다시 시도하세요.", username)
		return
	}
	s.store.RecordLogin(r.Context(), user.ID)
	setSessionCookie(w, token, time.Unix(data.ExpiresAt, 0))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) renderLogin(w http.ResponseWriter, r *http.Request, status int, pageError, username string) {
	w.Header().Set("Cache-Control", "no-store")
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
	_ = s.templates.ExecuteTemplate(w, "login.html", map[string]any{
		"Error": pageError, "Username": username, "PasswordChanged": r.URL.Query().Get("password_changed") == "1",
	})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		s.renderAdminError(w, r, http.StatusForbidden, "보안 정보가 만료되었습니다", "화면을 새로고침한 뒤 다시 시도하세요.")
		return
	}
	clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	session := sessionFrom(r)
	enterpriseID, ok := s.effectiveEnterpriseFilter(r, r.URL.Query().Get("enterprise_id"))
	if !ok {
		s.renderAdminError(w, r, http.StatusBadRequest, "기업 필터가 올바르지 않습니다", "활성 기업을 다시 선택하세요.")
		return
	}
	overview, err := s.loadOverview(r.Context(), overviewFilterFromRequest(r, enterpriseID), time.Now().UTC())
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "운영 현황을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	servers, err := s.store.ListServers(r.Context(), enterpriseID, 500)
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "서버 현황을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	groups, err := s.store.ListGroups(r.Context(), enterpriseID)
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "서버 그룹을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	data := map[string]any{"Overview": overview, "Servers": servers, "Groups": groups, "FilterEnterprise": enterpriseID, "FilterGroup": r.URL.Query().Get("group_id"), "FilterServer": r.URL.Query().Get("server_id")}
	if session.IsSystemAdmin() {
		enterprises, enterpriseErr := s.store.ListEnterprises(r.Context())
		if enterpriseErr != nil {
			s.renderAdminError(w, r, http.StatusInternalServerError, "기업 목록을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
			return
		}
		data["Enterprises"] = enterprises
	}
	if s.catalogErr != nil {
		data["Notice"] = "Package bundle을 사용할 수 없습니다: " + s.catalogErr.Error()
	}
	_ = s.templates.ExecuteTemplate(w, "dashboard.html", s.viewData(r, "dashboard", data))
}

func (s *Server) servers(w http.ResponseWriter, r *http.Request) {
	s.renderServers(w, r, http.StatusOK, "")
}

func (s *Server) renderServers(w http.ResponseWriter, r *http.Request, status int, pageError string) {
	session := sessionFrom(r)
	enterpriseID, ok := s.effectiveEnterpriseFilter(r, r.URL.Query().Get("enterprise_id"))
	if !ok {
		s.renderAdminError(w, r, http.StatusBadRequest, "기업 필터가 올바르지 않습니다", "활성 기업을 다시 선택하세요.")
		return
	}
	items, err := s.store.ListServers(r.Context(), enterpriseID, 500)
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "서버 목록을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	if s.catalog != nil {
		for i := range items {
			_, _, rollbackErr := s.catalog.Rollback(items[i].AgentPackageID, items[i].ModulePackageID)
			items[i].CanRollbackPackages = rollbackErr == nil
		}
	}
	groups, err := s.store.ListGroups(r.Context(), enterpriseID)
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "서버 그룹을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	groupID := truncate(strings.TrimSpace(r.URL.Query().Get("group_id")), 64)
	groupMembers := make(map[string]bool)
	if groupID != "" {
		for _, group := range groups {
			if group.ID == groupID {
				for _, member := range group.Members {
					groupMembers[member.ID] = true
				}
				break
			}
		}
	}
	queryText := strings.ToLower(truncate(strings.TrimSpace(r.URL.Query().Get("q")), 255))
	filterStatus := strings.ToUpper(truncate(strings.TrimSpace(r.URL.Query().Get("status")), 32))
	filtered := make([]ServerRecord, 0, len(items))
	for _, item := range items {
		if groupID != "" && !groupMembers[item.ID] {
			continue
		}
		if filterStatus == "REVOKED" {
			if !item.Revoked {
				continue
			}
		} else if filterStatus != "" && (item.Revoked || item.Status != filterStatus) {
			continue
		}
		if queryText != "" && !strings.Contains(strings.ToLower(item.Name+" "+item.Inventory.Hostname+" "+item.Inventory.WebServer), queryText) {
			continue
		}
		filtered = append(filtered, item)
	}
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
	hasServerFilter := strings.TrimSpace(r.URL.Query().Get("enterprise_id")) != "" || groupID != "" || filterStatus != "" || queryText != ""
	data := map[string]any{"Servers": filtered, "ServerTotal": len(items), "Groups": groups, "FilterEnterprise": enterpriseID, "FilterGroup": groupID, "FilterStatus": filterStatus, "FilterQuery": r.URL.Query().Get("q"), "HasServerFilter": hasServerFilter, "Notice": strings.TrimSpace(r.URL.Query().Get("notice")), "Error": pageError}
	if session.IsSystemAdmin() {
		enterprises, enterpriseErr := s.store.ListEnterprises(r.Context())
		if enterpriseErr != nil {
			s.renderAdminError(w, r, http.StatusInternalServerError, "기업 목록을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
			return
		}
		data["Enterprises"] = enterprises
	}
	_ = s.templates.ExecuteTemplate(w, "servers.html", s.viewData(r, "servers", data))
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	session := sessionFrom(r)
	enterpriseID, ok := s.effectiveEnterpriseFilter(r, r.URL.Query().Get("enterprise_id"))
	if !ok {
		s.renderAdminError(w, r, http.StatusBadRequest, "기업 필터가 올바르지 않습니다", "활성 기업을 다시 선택하세요.")
		return
	}
	eventFilter, rangeKey := eventFilterFromRequest(r, enterpriseID)
	category := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("category")))
	if !validateIncidentCategory(category) {
		category = ""
	}
	filter := IncidentFilter{EnterpriseID: enterpriseID, GroupID: eventFilter.GroupID, ServerID: eventFilter.ServerID, Category: category, Severity: eventFilter.Severity, RuleID: eventFilter.RuleID, Query: eventFilter.Query, Blocked: eventFilter.Blocked, Since: eventFilter.Since, CursorAt: eventFilter.CursorAt, CursorID: eventFilter.CursorID, CursorDirection: eventFilter.CursorDirection}
	page := queryPage(r)
	const pageSize = 100
	if filter.CursorDirection == "" {
		filter.Offset = (page - 1) * pageSize
	}
	items, err := s.store.ListIncidents(r.Context(), "", filter, pageSize+1)
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "이벤트 목록을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	pageResult := paginateIncidentRecords(items, pageSize, page, filter.CursorDirection)
	items = pageResult.Items
	servers, err := s.store.ListServers(r.Context(), enterpriseID, 500)
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "이벤트 필터를 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	groups, err := s.store.ListGroups(r.Context(), enterpriseID)
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "이벤트 그룹 필터를 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	data := map[string]any{"Events": items, "Servers": servers, "Groups": groups, "Range": rangeKey, "FilterEnterprise": enterpriseID, "FilterGroup": filter.GroupID, "FilterServer": filter.ServerID, "FilterCategory": category, "FilterQuery": filter.Query, "FilterResult": r.URL.Query().Get("result"), "FilterChips": eventFilterChips(r, session), "SelectedIncident": firstNonEmpty(r.URL.Query().Get("incident"), r.URL.Query().Get("event")), "Page": page, "HasNext": pageResult.HasNext, "Notice": r.URL.Query().Get("notice")}
	if session.IsSystemAdmin() {
		enterprises, enterpriseErr := s.store.ListEnterprises(r.Context())
		if enterpriseErr != nil {
			s.renderAdminError(w, r, http.StatusInternalServerError, "기업 목록을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
			return
		}
		data["Enterprises"] = enterprises
	}
	if pageResult.HasPrevious && len(items) != 0 {
		data["PreviousURL"] = eventPageURL(r, max(page-1, 1), encodeIncidentCursor(items[0], eventCursorAfter))
	}
	if pageResult.HasNext && len(items) != 0 {
		data["NextURL"] = eventPageURL(r, page+1, encodeIncidentCursor(items[len(items)-1], eventCursorBefore))
	}
	_ = s.templates.ExecuteTemplate(w, "events.html", s.viewData(r, "events", data))
}

func (s *Server) policies(w http.ResponseWriter, r *http.Request) {
	session := sessionFrom(r)
	systemPolicyID := truncate(strings.TrimSpace(r.URL.Query().Get("system_policy_id")), 255)
	filterQuery := truncate(strings.TrimSpace(r.URL.Query().Get("q")), 255)
	filterStrategy := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("strategy")))
	filterRollout := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("rollout")))
	enterpriseID, ok := s.effectiveEnterpriseFilter(r, r.URL.Query().Get("enterprise_id"))
	if !ok {
		s.renderAdminError(w, r, http.StatusBadRequest, "기업 필터가 올바르지 않습니다", "활성 기업을 다시 선택하세요.")
		return
	}
	var enterprises []EnterpriseRecord
	if session.IsSystemAdmin() {
		var enterpriseErr error
		enterprises, enterpriseErr = s.store.ListEnterprises(r.Context())
		if enterpriseErr != nil {
			s.renderAdminError(w, r, http.StatusInternalServerError, "기업 목록을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
			return
		}
		if enterpriseID == "" {
			data := map[string]any{
				"Policies":                    []EnterprisePolicyRecord{},
				"PolicyTotal":                 0,
				"Enterprises":                 enterprises,
				"FilterEnterprise":            "",
				"FilterSystemPolicyID":        systemPolicyID,
				"FilterQuery":                 filterQuery,
				"FilterStrategy":              filterStrategy,
				"FilterRollout":               filterRollout,
				"RequiresEnterpriseSelection": true,
			}
			_ = s.templates.ExecuteTemplate(w, "policies.html", s.viewData(r, "policies", data))
			return
		}
	}
	items, err := s.store.ListEnterprisePolicies(r.Context(), enterpriseID, 500)
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "기업 정책을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	policyTotal := len(items)
	filterLabel := ""
	if systemPolicyID != "" {
		filtered := make([]EnterprisePolicyRecord, 0, len(items))
		for _, item := range items {
			if item.CurrentSystemPolicyID == systemPolicyID {
				filtered = append(filtered, item)
			}
		}
		items = filtered
		filterLabel = systemPolicyID
		if policyTemplate, ok := s.systemPolicyTemplate(r.Context(), systemPolicyID); ok {
			filterLabel = policyTemplate.Name + " " + policyTemplate.Version
		}
	}
	query := strings.ToLower(filterQuery)
	filtered := make([]EnterprisePolicyRecord, 0, len(items))
	for _, item := range items {
		if query != "" && !strings.Contains(strings.ToLower(item.Name+" "+item.Description+" "+item.TargetLabel()), query) {
			continue
		}
		if filterStrategy != "" && item.UpdateStrategy != filterStrategy {
			continue
		}
		if filterRollout != "" && item.LatestRolloutStatus != filterRollout {
			continue
		}
		filtered = append(filtered, item)
	}
	hasPolicyFilter := systemPolicyID != "" || filterQuery != "" || filterStrategy != "" || filterRollout != ""
	data := map[string]any{"Policies": filtered, "PolicyTotal": policyTotal, "FilterEnterprise": enterpriseID, "FilterSystemPolicyID": systemPolicyID, "FilterSystemPolicyLabel": filterLabel, "FilterQuery": filterQuery, "FilterStrategy": filterStrategy, "FilterRollout": filterRollout, "HasPolicyFilter": hasPolicyFilter}
	if session.IsSystemAdmin() {
		data["Enterprises"] = enterprises
	}
	_ = s.templates.ExecuteTemplate(w, "policies.html", s.viewData(r, "policies", data))
}

func (s *Server) newPolicy(w http.ResponseWriter, r *http.Request) {
	s.renderPolicyForm(w, r, http.StatusOK, "", nil)
}

func policyFormState(r *http.Request) map[string]any {
	return map[string]any{
		"FormEnterpriseID":          strings.TrimSpace(r.FormValue("enterprise_id")),
		"FormTemplateKey":           strings.TrimSpace(r.FormValue("template_key")),
		"FormName":                  truncate(strings.TrimSpace(r.FormValue("name")), 255),
		"FormDescription":           truncate(strings.TrimSpace(r.FormValue("description")), 1024),
		"FormTarget":                strings.TrimSpace(r.FormValue("target")),
		"FormStrategy":              strings.TrimSpace(r.FormValue("update_strategy")),
		"FormMode":                  strings.TrimSpace(r.FormValue("mode")),
		"FormParanoia":              strings.TrimSpace(r.FormValue("paranoia_level")),
		"FormExecutingParanoia":     strings.TrimSpace(r.FormValue("executing_paranoia_level")),
		"FormScore":                 strings.TrimSpace(r.FormValue("inbound_score")),
		"FormOutboundScore":         strings.TrimSpace(r.FormValue("outbound_score")),
		"FormRequestBody":           r.FormValue("request_body") == "on",
		"FormResponseBody":          r.FormValue("response_body") == "on",
		"FormEarlyBlocking":         r.FormValue("early_blocking") == "on",
		"FormSamplingPercentage":    strings.TrimSpace(r.FormValue("sampling_percentage")),
		"FormExcludedPaths":         r.FormValue("excluded_paths"),
		"FormExcludedIPs":           r.FormValue("excluded_ips"),
		"FormRuleExclusions":        r.FormValue("rule_exclusions"),
		"FormTagExclusions":         r.FormValue("tag_exclusions"),
		"FormTargetExclusions":      r.FormValue("target_exclusions"),
		"FormConditionalExclusions": r.FormValue("conditional_exclusions"),
		"FormBypassField":           r.FormValue("bypass_field"),
		"FormBypassOperator":        r.FormValue("bypass_operator"),
		"FormBypassValue":           r.FormValue("bypass_value"),
		"FormBypassReason":          r.FormValue("bypass_reason"),
		"FormBypassExpiresAt":       r.FormValue("bypass_expires_at"),
		"FormCustomRules":           r.FormValue("custom_rules"),
		"FormGuidedRules":           r.FormValue("guided_rules_json"),
	}
}

func (s *Server) renderPolicyForm(w http.ResponseWriter, r *http.Request, status int, pageError string, form map[string]any) {
	requestedEnterpriseID := strings.TrimSpace(r.URL.Query().Get("enterprise_id"))
	if value, exists := form["FormEnterpriseID"]; exists {
		if formEnterpriseID, valueOK := value.(string); valueOK && strings.TrimSpace(formEnterpriseID) != "" {
			requestedEnterpriseID = strings.TrimSpace(formEnterpriseID)
		}
	}
	enterpriseID, scopeOK := s.effectiveEnterpriseFilter(r, requestedEnterpriseID)
	if !scopeOK || enterpriseID == "" {
		s.renderAdminError(w, r, http.StatusBadRequest, "운영 기업을 선택해야 합니다", "보호 정책 목록에서 기업을 선택한 뒤 다시 시도하세요.")
		return
	}
	servers, err := s.store.ListServers(r.Context(), enterpriseID, 500)
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "정책 대상을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	groups, err := s.store.ListGroups(r.Context(), enterpriseID)
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "서버 그룹을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	defaultTemplate := s.defaultSystemPolicyTemplate(r.Context())
	requestedKey := strings.TrimSpace(r.URL.Query().Get("template_key"))
	if value, ok := form["FormTemplateKey"].(string); ok && strings.TrimSpace(value) != "" {
		requestedKey = strings.TrimSpace(value)
	}
	if requestedKey != "" {
		if requested, ok := s.latestSystemPolicyTemplate(r.Context(), requestedKey); ok {
			defaultTemplate = requested
		}
	}
	policyTemplates, err := s.publishedSystemPolicyTemplates(r.Context())
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "시스템 정책을 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	targetEnterprises, err := s.store.ListEnterprises(r.Context())
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "기업 범위를 불러올 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	allEnterprises := targetEnterprises
	targetEnterpriseIDs := make(map[string]bool)
	for _, server := range servers {
		if !server.Revoked {
			targetEnterpriseIDs[server.EnterpriseID] = true
		}
	}
	filteredEnterprises := make([]EnterpriseRecord, 0, 1)
	for _, enterprise := range targetEnterprises {
		if targetEnterpriseIDs[enterprise.ID] && enterprise.ID == enterpriseID {
			filteredEnterprises = append(filteredEnterprises, enterprise)
		}
	}
	targetEnterprises = filteredEnterprises
	data := map[string]any{
		"Servers": servers, "Groups": groups, "PolicyTargetEnterprises": targetEnterprises, "PolicyTemplates": policyTemplates, "DefaultTemplate": defaultTemplate,
		"Error": pageError, "FormTemplateKey": defaultTemplate.Key, "FormStrategy": PolicyStrategyManual, "FormMode": defaultTemplate.Defaults.Mode,
		"FormParanoia": strconv.Itoa(defaultTemplate.Defaults.ParanoiaLevel), "FormExecutingParanoia": strconv.Itoa(defaultTemplate.Defaults.ExecutingParanoiaLevel),
		"FormScore": strconv.Itoa(defaultTemplate.Defaults.InboundScore), "FormOutboundScore": strconv.Itoa(defaultTemplate.Defaults.OutboundScore),
		"FormRequestBody": defaultTemplate.Defaults.RequestBody, "FormResponseBody": defaultTemplate.Defaults.ResponseBody,
		"FormEarlyBlocking": defaultTemplate.Defaults.EarlyBlocking, "FormSamplingPercentage": strconv.Itoa(defaultTemplate.Defaults.SamplingPercentage),
		"FormBypassExpiresAt": localtime.FormatKST(time.Now().Add(24*time.Hour), "2006-01-02T15:04"),
	}
	for key, value := range form {
		data[key] = value
	}
	data["FormEnterpriseID"] = enterpriseID
	data["FilterEnterpriseID"] = enterpriseID
	data["Enterprises"] = allEnterprises
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
	_ = s.templates.ExecuteTemplate(w, "policy.html", s.viewData(r, "policies", data))
}

func (s *Server) createPolicy(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		s.renderAdminError(w, r, http.StatusForbidden, "보안 정보가 만료되었습니다", "화면을 새로고침한 뒤 다시 시도하세요.")
		return
	}
	form := policyFormState(r)
	if r.FormValue("publish_confirm") != "confirmed" {
		s.renderPolicyForm(w, r, http.StatusBadRequest, "변경 내용과 단계 배포 영향을 확인해야 합니다.", form)
		return
	}
	name := truncate(strings.TrimSpace(r.FormValue("name")), 255)
	description := truncate(strings.TrimSpace(r.FormValue("description")), 1024)
	target := strings.TrimSpace(r.FormValue("target"))
	templateKey := strings.TrimSpace(r.FormValue("template_key"))
	if templateKey == "" {
		templateKey = s.defaultSystemPolicyTemplate(r.Context()).Key
	}
	policyTemplate, ok := s.latestSystemPolicyTemplate(r.Context(), templateKey)
	if !ok {
		s.renderPolicyForm(w, r, http.StatusBadRequest, "지원하지 않는 시스템 정책 템플릿입니다.", form)
		return
	}
	mode := strings.TrimSpace(r.FormValue("mode"))
	paranoiaLevel, paranoiaErr := strconv.Atoi(strings.TrimSpace(r.FormValue("paranoia_level")))
	executingParanoiaLevel, executingErr := strconv.Atoi(strings.TrimSpace(r.FormValue("executing_paranoia_level")))
	inboundScore, scoreErr := strconv.Atoi(strings.TrimSpace(r.FormValue("inbound_score")))
	outboundScore, outboundErr := strconv.Atoi(strings.TrimSpace(r.FormValue("outbound_score")))
	samplingPercentage, samplingErr := strconv.Atoi(strings.TrimSpace(r.FormValue("sampling_percentage")))
	if name == "" || target == "" || paranoiaErr != nil || executingErr != nil || scoreErr != nil || outboundErr != nil || samplingErr != nil {
		s.renderPolicyForm(w, r, http.StatusBadRequest, "정책 이름, 대상과 유효한 세부 설정을 확인하세요.", form)
		return
	}
	strategy := strings.TrimSpace(r.FormValue("update_strategy"))
	if strategy == "" {
		strategy = PolicyStrategyManual
	}
	if strategy != PolicyStrategyManual && strategy != PolicyStrategyAutomatic && strategy != PolicyStrategyPinned {
		s.renderPolicyForm(w, r, http.StatusBadRequest, "지원하지 않는 업데이트 전략입니다.", form)
		return
	}
	metadata := ManagedPolicyMetadata{
		SchemaVersion: policyTemplate.SchemaVersion, TemplateKey: policyTemplate.Key, TemplateVersion: policyTemplate.Version,
		CRSTrack: policyTemplate.CRSTrack, CRSVersion: policyTemplate.CRSVersion, Target: target,
		AutoUpdate: strategy == PolicyStrategyAutomatic, PolicyOrigin: "administrator", MigrationStatus: "CURRENT",
	}
	guidedRules, guidedErr := guidedRulesFromForm(r)
	customRules, mergeErr := mergeGuidedPolicyRules(r.FormValue("custom_rules"), guidedRules)
	if guidedErr != nil || mergeErr != nil {
		message := "안내형 규칙 입력이 올바르지 않습니다."
		if guidedErr != nil {
			message = guidedErr.Error()
		} else if mergeErr != nil {
			message = mergeErr.Error()
		}
		s.renderPolicyForm(w, r, http.StatusBadRequest, message, form)
		return
	}
	exclusions, exclusionErr := enterprisePolicyExclusionsFromForm(r)
	if exclusionErr != nil {
		s.renderPolicyForm(w, r, http.StatusBadRequest, "정책 예외가 올바르지 않습니다: "+exclusionErr.Error(), form)
		return
	}
	_, _, err := buildEnterprisePolicyArtifact(policyTemplate, mode, paranoiaLevel, inboundScore, r.FormValue("request_body") == "on", r.FormValue("excluded_paths"), r.FormValue("excluded_ips"), customRules, metadata)
	if err != nil {
		s.renderPolicyForm(w, r, http.StatusBadRequest, "정책 설정이 올바르지 않습니다: "+err.Error(), form)
		return
	}
	session := sessionFrom(r)
	selectedEnterpriseID, ok := s.requestEnterpriseID(r)
	if !ok {
		s.renderPolicyForm(w, r, http.StatusBadRequest, "운영 기업을 다시 선택하세요.", form)
		return
	}
	enterpriseID, serverIDs, err := s.store.ResolvePolicyTarget(r.Context(), selectedEnterpriseID, target)
	if err != nil {
		s.renderPolicyForm(w, r, http.StatusBadRequest, "정책 대상을 찾을 수 없습니다: "+err.Error(), form)
		return
	}
	servers, err := s.store.ListServers(r.Context(), enterpriseID, systemPolicyServerLimit)
	if err != nil {
		s.renderPolicyForm(w, r, http.StatusInternalServerError, "정책 대상 서버를 불러올 수 없습니다. 잠시 후 다시 시도하세요.", form)
		return
	}
	policyID := randomID()
	existingPolicies, err := s.store.ListEnterprisePolicies(r.Context(), enterpriseID, systemPolicyServerLimit)
	if err != nil {
		s.renderPolicyForm(w, r, http.StatusInternalServerError, "기존 기업 정책을 불러올 수 없습니다. 잠시 후 다시 시도하세요.", form)
		return
	}
	candidate := EnterprisePolicyRecord{ID: policyID, EnterpriseID: enterpriseID, Target: target, Status: EnterprisePolicyActive, CurrentRevisionID: "candidate", UpdatedAt: time.Now().UTC()}
	winners, err := s.enterprisePolicyWinners(r.Context(), append(existingPolicies, candidate), servers)
	if err != nil {
		s.renderPolicyForm(w, r, http.StatusInternalServerError, "정책 우선순위를 확인할 수 없습니다. 잠시 후 다시 시도하세요.", form)
		return
	}
	serverIDs = orderIDsByServers(winners[policyID], servers)
	if len(serverIDs) == 0 {
		s.renderPolicyForm(w, r, http.StatusBadRequest, "정책 대상에 실제로 적용 가능한 서버가 없습니다. 정책 우선순위와 대상 구성을 확인하세요.", form)
		return
	}
	settings := PolicySettings{
		SchemaVersion: policyTemplate.SchemaVersion, TemplateKey: policyTemplate.Key, TemplateVersion: policyTemplate.Version,
		CRSTrack: policyTemplate.CRSTrack, CRSVersion: policyTemplate.CRSVersion, Target: target, AutoUpdate: strategy == PolicyStrategyAutomatic,
		PolicyOrigin: "administrator", MigrationStatus: "CURRENT", ParanoiaLevel: paranoiaLevel,
		ExecutingParanoiaLevel: executingParanoiaLevel, InboundScore: inboundScore, OutboundScore: outboundScore,
		RequestBody: r.FormValue("request_body") == "on", ResponseBody: r.FormValue("response_body") == "on",
		EarlyBlocking: r.FormValue("early_blocking") == "on", SamplingPercentage: samplingPercentage, ExcludedPaths: uniqueNonEmptyLines(r.FormValue("excluded_paths")),
		ExcludedIPs: uniqueNonEmptyLines(r.FormValue("excluded_ips")), Exclusions: exclusions, CustomRules: customRules,
	}
	origin := "administrator"
	if r.FormValue("confirm_legacy_policy") == "confirmed" {
		origin = "administrator-legacy-confirmed"
	}
	revision, fullPath, err := s.preparePolicyRevision(policyTemplate, name, description, mode, settings, "", origin)
	if err != nil {
		s.renderPolicyForm(w, r, http.StatusBadRequest, "정책 개정본을 만들 수 없습니다: "+err.Error(), form)
		return
	}
	rolloutID, err := s.store.CreateEnterprisePolicyWithRollout(r.Context(), enterpriseID, policyID, name, description, target, policyTemplate.Key, strategy, session.UserID, revision, "SEED", "QUEUED", serverIDs)
	if err != nil {
		_ = os.Remove(fullPath)
		if errors.Is(err, sql.ErrNoRows) {
			s.renderPolicyForm(w, r, http.StatusNotFound, "정책 대상 서버를 찾을 수 없습니다. 대상을 다시 선택하세요.", form)
			return
		}
		s.renderPolicyForm(w, r, http.StatusInternalServerError, "기업 정책을 생성할 수 없습니다. 잠시 후 다시 시도하세요.", form)
		return
	}
	s.audit(r, session.Username, "enterprise_policy.create", policyID+":"+rolloutID, "success")
	s.TriggerPolicySync()
	http.Redirect(w, r, "/policies/"+policyID+"?notice="+url.QueryEscape("기업 정책이 "+strconv.Itoa(len(serverIDs))+"대 서버에 단계 배포 대기 중입니다."), http.StatusSeeOther)
}

func (s *Server) newEnrollment(w http.ResponseWriter, r *http.Request) {
	s.renderEnrollment(w, r, nil)
}

func (s *Server) createEnrollment(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		s.renderAdminError(w, r, http.StatusForbidden, "보안 정보가 만료되었습니다", "화면을 새로고침한 뒤 다시 시도하세요.")
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderEnrollment(w, r, map[string]any{"Status": http.StatusBadRequest, "Error": "입력 내용을 읽을 수 없습니다. 다시 입력해 주세요."})
		return
	}
	label := truncate(strings.TrimSpace(r.FormValue("label")), 255)
	if label == "" {
		s.renderEnrollment(w, r, map[string]any{"Status": http.StatusBadRequest, "Error": "서버 식별 이름을 입력하세요.", "FormEnterpriseID": strings.TrimSpace(r.FormValue("enterprise_id"))})
		return
	}
	enterpriseID, ok := s.requestEnterpriseID(r)
	if !ok {
		s.renderEnrollment(w, r, map[string]any{"Status": http.StatusBadRequest, "Error": "유효한 기업을 선택하세요.", "FormEnterpriseID": strings.TrimSpace(r.FormValue("enterprise_id")), "FormEnrollmentLabel": label})
		return
	}
	token, expires, err := s.store.CreateEnrollmentToken(r.Context(), enterpriseID, label, s.cfg.EnrollmentTTL)
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "일회용 등록 토큰을 만들 수 없습니다", "잠시 후 다시 시도하세요.")
		return
	}
	s.audit(r, sessionFrom(r).Username, "enrollment.create", label, "success")
	s.renderEnrollment(w, r, map[string]any{"Token": token, "ExpiresAt": expires, "FormEnterpriseID": enterpriseID})
}

func (s *Server) apiServers(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListServers(r.Context(), sessionFrom(r).ScopeEnterpriseID(), 500)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "load servers")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) apiEvents(w http.ResponseWriter, r *http.Request) {
	enterpriseID, ok := s.effectiveEnterpriseFilter(r, r.URL.Query().Get("enterprise_id"))
	if !ok {
		writeProblem(w, http.StatusBadRequest, "invalid enterprise filter")
		return
	}
	filter, rangeKey := eventFilterFromRequest(r, enterpriseID)
	page := queryPage(r)
	pageSize := 100
	if requested, parseErr := strconv.Atoi(r.URL.Query().Get("page_size")); parseErr == nil && requested >= 1 && requested <= 500 {
		pageSize = requested
	}
	if filter.CursorDirection == "" {
		filter.Offset = (page - 1) * pageSize
	}
	items, err := s.store.ListEventsFiltered(r.Context(), "", filter, pageSize+1)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "load events")
		return
	}
	pageResult := paginateEventRecords(items, pageSize, page, filter.CursorDirection)
	items = pageResult.Items
	previousCursor, nextCursor := "", ""
	if pageResult.HasPrevious && len(items) != 0 {
		previousCursor = encodeEventCursor(items[0], eventCursorAfter)
	}
	if pageResult.HasNext && len(items) != 0 {
		nextCursor = encodeEventCursor(items[len(items)-1], eventCursorBefore)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "page": page, "page_size": pageSize, "has_previous": pageResult.HasPrevious, "has_next": pageResult.HasNext, "previous_cursor": previousCursor, "next_cursor": nextCursor, "range": rangeKey, "generated_at": time.Now().UTC()})
}

func (s *Server) apiCreateEnrollment(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		writeProblem(w, http.StatusForbidden, "invalid csrf token")
		return
	}
	var request struct {
		EnterpriseID string `json:"enterprise_id"`
		Label        string `json:"label"`
	}
	if err := decodeJSON(w, r, &request, 16<<10); err != nil {
		return
	}
	request.Label = truncate(strings.TrimSpace(request.Label), 255)
	if request.Label == "" {
		writeProblem(w, http.StatusBadRequest, "label is required")
		return
	}
	enterpriseID, ok := s.enterpriseIDForSession(r.Context(), sessionFrom(r), strings.TrimSpace(request.EnterpriseID))
	if !ok {
		writeProblem(w, http.StatusBadRequest, "valid enterprise is required")
		return
	}
	token, expires, err := s.store.CreateEnrollmentToken(r.Context(), enterpriseID, request.Label, s.cfg.EnrollmentTTL)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "create enrollment")
		return
	}
	s.audit(r, sessionFrom(r).Username, "enrollment.create", request.Label, "success")
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, map[string]any{"token": token, "expires_at": expires, "agent_api": s.cfg.PublicURL})
}

func (s *Server) bootstrapInstaller(w http.ResponseWriter, _ *http.Request) {
	raw, err := bootstrapFiles.ReadFile("bootstrap-install.sh")
	if err != nil {
		http.Error(w, "installer unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="mwaf-install.sh"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(raw)
}

func (s *Server) resolvePackages(w http.ResponseWriter, r *http.Request) {
	if s.catalog == nil {
		writeProblem(w, http.StatusServiceUnavailable, "package bundle unavailable")
		return
	}
	var request struct {
		Token     string          `json:"token"`
		Inventory model.Inventory `json:"inventory"`
	}
	if err := decodeJSON(w, r, &request, 64<<10); err != nil {
		return
	}
	if err := s.store.ValidateEnrollmentToken(r.Context(), request.Token); err != nil {
		writeProblem(w, http.StatusUnauthorized, "invalid enrollment token")
		return
	}
	var agent, module model.PackageArtifact
	var err error
	packageIDs := make([]string, 0, 2)
	if request.Inventory.InstallationMode == "manual" {
		agent, err = s.catalog.ResolveAgent(request.Inventory)
		packageIDs = append(packageIDs, agent.ID)
	} else {
		agent, module, err = s.catalog.Resolve(request.Inventory)
		packageIDs = append(packageIDs, agent.ID, module.ID)
	}
	if err != nil {
		writeProblem(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if err := s.store.AllowEnrollmentPackages(r.Context(), request.Token, packageIDs); err != nil {
		writeProblem(w, http.StatusUnauthorized, "invalid enrollment token")
		return
	}
	expires := time.Now().UTC().Add(s.cfg.EnrollmentTTL)
	moduleDownload := model.PackageDownload{}
	if module.ID != "" {
		moduleDownload = packageDownload(s.cfg.PublicURL, module)
	}
	resolution := model.PackageResolution{
		BundleVersion: s.catalog.Manifest().BundleVersion,
		ExpiresAt:     expires,
		Agent:         packageDownload(s.cfg.PublicURL, agent),
		Module:        moduleDownload,
	}
	if strings.Contains(r.Header.Get("Accept"), "text/plain") {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprintf(w, "%s\n%s\n%s\n%s\n%s\n", resolution.BundleVersion, resolution.Agent.URL, resolution.Agent.SHA256, resolution.Module.URL, resolution.Module.SHA256)
		return
	}
	writeJSON(w, http.StatusOK, resolution)
}

func (s *Server) bootstrapPackage(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if token == "" {
		writeProblem(w, http.StatusUnauthorized, "bearer enrollment token required")
		return
	}
	id := r.PathValue("id")
	allowed, err := s.store.EnrollmentPackageAllowed(r.Context(), token, id)
	if err != nil || !allowed {
		writeProblem(w, http.StatusForbidden, "package is not allowed for this enrollment")
		return
	}
	if !s.downloadLimiter.allow(fmt.Sprintf("%x", tokenHash(token))) {
		w.Header().Set("Retry-After", "60")
		writeProblem(w, http.StatusTooManyRequests, "package download limit exceeded")
		return
	}
	s.servePackage(w, r, id)
}

func (s *Server) packagePublicKey(w http.ResponseWriter, _ *http.Request) {
	raw, err := os.ReadFile(s.cfg.BundlePublicKey)
	if err != nil {
		http.Error(w, "package key unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write(raw)
}

func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	var request model.EnrollRequest
	if err := decodeJSON(w, r, &request, 128<<10); err != nil {
		return
	}
	if err := s.store.ValidateEnrollmentToken(r.Context(), request.Token); err != nil {
		writeProblem(w, http.StatusUnauthorized, "invalid enrollment token")
		return
	}
	serverID := randomID()
	certificate, serial, _, err := s.ca.SignAgentCSR(request.CSRPEM, serverID)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid agent certificate request")
		return
	}
	name := truncate(strings.TrimSpace(request.Name), 255)
	if name == "" {
		name = truncate(request.Inventory.Hostname, 255)
	}
	if err := s.store.ConsumeEnrollment(r.Context(), request.Token, serverID, name, serial, request.Inventory); err != nil {
		if errors.Is(err, ErrInvalidEnrollmentToken) {
			writeProblem(w, http.StatusUnauthorized, "invalid enrollment token")
		} else {
			writeProblem(w, http.StatusInternalServerError, "enrollment failed")
		}
		return
	}
	s.TriggerPolicySync()
	writeJSON(w, http.StatusCreated, model.EnrollResponse{ServerID: serverID, CertificatePEM: certificate, CACertificate: s.ca.CertificatePEM(), PolicyPublicKey: s.policySigner.PublicPEM(), AgentAPI: s.cfg.PublicURL})
}

func (s *Server) renewCertificate(w http.ResponseWriter, r *http.Request) {
	var request model.CertificateRenewRequest
	if err := decodeJSON(w, r, &request, 64<<10); err != nil {
		return
	}
	serverID := agentIDFrom(r)
	certificate, _, expiresAt, err := s.ca.SignAgentCSR(request.CSRPEM, serverID)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid agent certificate request")
		return
	}
	writeJSON(w, http.StatusOK, model.CertificateRenewResponse{CertificatePEM: certificate, ExpiresAt: expiresAt})
}

func (s *Server) heartbeat(w http.ResponseWriter, r *http.Request) {
	var request model.HeartbeatRequest
	if err := decodeJSON(w, r, &request, 128<<10); err != nil {
		return
	}
	if request.Status == "" {
		request.Status = "ONLINE"
	}
	if err := s.store.UpdateHeartbeat(r.Context(), agentIDFrom(r), request); err != nil {
		writeProblem(w, http.StatusInternalServerError, "heartbeat failed")
		return
	}
	s.TriggerPolicySync()
	writeJSON(w, http.StatusOK, map[string]any{"accepted": true, "server_time": time.Now().UTC()})
}

func (s *Server) desiredState(w http.ResponseWriter, r *http.Request) {
	state, err := s.store.DesiredState(r.Context(), agentIDFrom(r))
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "load desired state")
		return
	}
	if state.RevisionID != "" {
		state.ArtifactURL = protocol.PolicyArtifactPath(state.RevisionID)
	}
	if state.PackageDeployment != nil {
		if s.catalog == nil {
			writeProblem(w, http.StatusServiceUnavailable, "package bundle unavailable")
			return
		}
		agentArtifact, agentOK := s.catalog.Artifact(state.AgentPackageID)
		moduleArtifact, moduleOK := s.catalog.Artifact(state.ModulePackageID)
		if !agentOK || !moduleOK {
			writeProblem(w, http.StatusServiceUnavailable, "assigned package is unavailable")
			return
		}
		state.PackageDeployment.Agent = agentPackageDownload(agentArtifact)
		state.PackageDeployment.Module = agentPackageDownload(moduleArtifact)
	}
	writeJSON(w, http.StatusOK, state)
}

func (s *Server) policyPublicKey(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = io.WriteString(w, s.policySigner.PublicPEM())
}

func (s *Server) policyArtifact(w http.ResponseWriter, r *http.Request) {
	revisionID := r.PathValue("id")
	artifact, err := s.store.PolicyArtifactForServer(r.Context(), agentIDFrom(r), revisionID)
	if err != nil {
		writeProblem(w, http.StatusNotFound, "policy artifact not assigned")
		return
	}
	clean := filepath.Clean(filepath.FromSlash(artifact.Path))
	if filepath.IsAbs(clean) || clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		writeProblem(w, http.StatusInternalServerError, "invalid policy artifact path")
		return
	}
	file, err := os.Open(filepath.Join(s.cfg.ArtifactRoot, clean))
	if err != nil {
		writeProblem(w, http.StatusNotFound, "policy artifact unavailable")
		return
	}
	defer file.Close()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Checksum-SHA256", artifact.SHA256)
	w.Header().Set("X-Artifact-Signature", artifact.Signature)
	w.Header().Set("Cache-Control", "private, no-store")
	_, _ = io.Copy(w, io.LimitReader(file, 1<<20))
}

func (s *Server) agentPackage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	allowed, err := s.store.PackageAllowedForServer(r.Context(), agentIDFrom(r), id)
	if err != nil || !allowed {
		writeProblem(w, http.StatusForbidden, "package is not assigned to this server")
		return
	}
	s.servePackage(w, r, id)
}

func (s *Server) servePackage(w http.ResponseWriter, r *http.Request, id string) {
	if s.catalog == nil {
		writeProblem(w, http.StatusServiceUnavailable, "package bundle unavailable")
		return
	}
	artifact, file, err := s.catalog.Open(id)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeProblem(w, http.StatusNotFound, "package not found")
		} else {
			writeProblem(w, http.StatusInternalServerError, "open package")
		}
		return
	}
	defer file.Close()
	contentType := mime.TypeByExtension(filepath.Ext(artifact.Path))
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filepath.Base(artifact.Path)))
	w.Header().Set("X-Checksum-SHA256", artifact.SHA256)
	w.Header().Set("Cache-Control", "private, no-store")
	http.ServeContent(w, r, filepath.Base(artifact.Path), s.catalog.Manifest().CreatedAt, file)
}

func (s *Server) eventBatch(w http.ResponseWriter, r *http.Request) {
	var batch model.EventBatch
	if err := decodeJSON(w, r, &batch, 4<<20); err != nil {
		return
	}
	if batch.BatchID == "" || len(batch.Events) == 0 || len(batch.Events) > 500 {
		writeProblem(w, http.StatusBadRequest, "batch_id and 1..500 events are required")
		return
	}
	batch.BatchID = truncate(batch.BatchID, 128)
	now := time.Now().UTC()
	for i := range batch.Events {
		event := &batch.Events[i]
		if event.EventID == "" {
			event.EventID = randomID()
		}
		if event.OccurredAt.IsZero() || event.OccurredAt.After(now.Add(5*time.Minute)) {
			event.OccurredAt = now
		}
		event.URI = truncate(event.URI, 2048)
		event.RequestID = truncate(strings.TrimSpace(event.RequestID), 128)
		event.TransactionID = truncate(strings.TrimSpace(event.TransactionID), 255)
		event.Service = truncate(strings.TrimSpace(event.Service), 255)
		event.Method = truncate(strings.TrimSpace(event.Method), 16)
		event.ClientIP, _ = canonicalEventIP(event.ClientIP)
		event.CountryCode = s.geoIP.CountryCode(event.ClientIP)
		event.Message = truncate(event.Message, 2048)
		event.MatchedVariable = truncate(strings.TrimSpace(event.MatchedVariable), 512)
		event.RuleID = truncate(event.RuleID, 64)
		event.RuleTags = normalizeEventRuleTags(event.RuleTags)
	}
	s.enrichEventRuleTags(r.Context(), batch.Events)
	duplicate, err := s.store.InsertEventBatch(r.Context(), agentIDFrom(r), batch)
	if err != nil {
		w.Header().Set("Retry-After", "5")
		writeProblem(w, http.StatusServiceUnavailable, "event storage unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"accepted": true, "duplicate": duplicate, "count": len(batch.Events)})
}

func (s *Server) unregisterAgent(w http.ResponseWriter, r *http.Request) {
	serverID := agentIDFrom(r)
	if err := s.store.UnregisterAgent(r.Context(), serverID); err != nil && !errors.Is(err, sql.ErrNoRows) {
		writeProblem(w, http.StatusServiceUnavailable, "agent unregister unavailable")
		return
	}
	_ = s.store.Audit(r.Context(), requestID(r), "agent:"+serverID, "agent.unregister", serverID, "success", remoteIP(r))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		data, err := s.sessions.parse(cookie.Value)
		if err != nil {
			clearSessionCookie(w)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		user, err := s.store.UserByID(r.Context(), data.UserID)
		if err != nil || !user.Active {
			clearSessionCookie(w)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if !secureEqual([]byte(data.CredentialTag), []byte(s.sessions.credentialTag(user.PasswordHash))) {
			clearSessionCookie(w)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		data.Username = user.Username
		data.DisplayName = user.DisplayName
		data.Role = user.Role
		data.ActualRole = user.Role
		data.ConsoleArea = ""
		data.EnterpriseID = user.EnterpriseID
		data.EnterpriseName = user.EnterpriseName
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), contextSession, data)))
	})
}

func (s *Server) requireEnterpriseConsole(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data := sessionFrom(r).asEnterpriseConsole()
		r = r.WithContext(context.WithValue(r.Context(), contextSession, data))
		if strings.TrimSpace(data.EnterpriseID) == "" {
			s.renderAdminError(w, r, http.StatusForbidden, "소속 기업을 확인할 수 없습니다", "기업 운영을 사용하려면 시스템 관리자 계정에도 소속 기업이 필요합니다.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireSystemConsole(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data := sessionFrom(r)
		if !data.CanAccessSystemManagement() {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		data = data.asSystemConsole()
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), contextSession, data)))
	})
}

func (s *Server) requireAccountConsole(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("area") == string(ConsoleAreaSystem) {
			s.requireSystemConsole(next).ServeHTTP(w, r)
			return
		}
		s.requireEnterpriseConsole(next).ServeHTTP(w, r)
	})
}

func (s *Server) limitBootstrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := remoteIP(r) + "|" + r.URL.Path
		if !s.bootstrapLimiter.allow(key) {
			w.Header().Set("Retry-After", "60")
			writeProblem(w, http.StatusTooManyRequests, "bootstrap request limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireRole(required Role, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !roleAtLeast(sessionFrom(r).Role, required) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireAgent(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
			writeProblem(w, http.StatusUnauthorized, "valid agent client certificate required")
			return
		}
		serverID := r.TLS.VerifiedChains[0][0].Subject.CommonName
		if serverID == "" {
			writeProblem(w, http.StatusUnauthorized, "agent certificate identity missing")
			return
		}
		if err := s.store.AuthorizeAgent(r.Context(), serverID, r.TLS.VerifiedChains[0][0]); err != nil {
			writeProblem(w, http.StatusUnauthorized, "agent certificate is unknown or revoked")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), contextAgentID, serverID)))
	})
}

func (s *Server) requireEventVerification(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimSpace(r.Header.Get(protocol.EventVerificationHeader))
		if token == "" {
			writeProblem(w, http.StatusUnauthorized, "event verification token required")
			return
		}
		if err := s.store.AuthorizeEventIngestToken(r.Context(), agentIDFrom(r), token); err != nil {
			writeProblem(w, http.StatusUnauthorized, "event verification token is invalid")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) validCSRF(r *http.Request) bool {
	if err := r.ParseForm(); err != nil {
		return false
	}
	provided := r.FormValue("csrf")
	if provided == "" {
		provided = r.Header.Get("X-CSRF-Token")
	}
	return secureEqual([]byte(provided), []byte(sessionFrom(r).CSRF))
}

func (s *Server) audit(r *http.Request, actor, action, target, result string) {
	session := sessionFrom(r)
	if session.ConsoleArea == ConsoleAreaEnterprise && session.CanAccessSystemManagement() && !session.IsSystemAdmin() {
		target += "|console=enterprise|effective_role=" + string(session.Role) + "|enterprise=" + session.EnterpriseID
	}
	if err := s.store.Audit(r.Context(), requestID(r), actor, action, target, result, remoteIP(r)); err != nil {
		s.logger.Error("admin audit write failed", "request_id", requestID(r), "actor", actor, "action", action, "error", err)
	}
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		if s.cfg.DevLiveReload {
			w.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := randomID()
		w.Header().Set("X-Request-ID", id)
		start := time.Now()
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), contextKey("request_id"), id)))
		s.logger.Info("http_request", "request_id", id, "method", r.Method, "path", r.URL.Path, "remote", remoteIP(r), "duration_ms", time.Since(start).Milliseconds())
	})
}

func packageDownload(base string, artifact model.PackageArtifact) model.PackageDownload {
	return model.PackageDownload{ID: artifact.ID, Name: artifact.Name, Version: artifact.Version, URL: base + protocol.BootstrapPackagePath(artifact.ID), Size: artifact.Size, SHA256: artifact.SHA256, RollbackID: artifact.RollbackID}
}

func agentPackageDownload(artifact model.PackageArtifact) model.PackageDownload {
	return model.PackageDownload{ID: artifact.ID, Name: artifact.Name, Version: artifact.Version, URL: protocol.AgentPackagePath(artifact.ID), Size: artifact.Size, SHA256: artifact.SHA256, RollbackID: artifact.RollbackID}
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any, limit int64) error {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid JSON request")
		return err
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeProblem(w, http.StatusBadRequest, "request must contain one JSON object")
		return errors.New("trailing JSON data")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeProblem(w http.ResponseWriter, status int, detail string) {
	writeJSON(w, status, map[string]any{"status": status, "detail": detail})
}

func sessionFrom(r *http.Request) sessionData {
	data, _ := r.Context().Value(contextSession).(sessionData)
	return data
}

func agentIDFrom(r *http.Request) string {
	id, _ := r.Context().Value(contextAgentID).(string)
	return id
}

func requestID(r *http.Request) string {
	id, _ := r.Context().Value(contextKey("request_id")).(string)
	return id
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func bearerToken(r *http.Request) string {
	value := r.Header.Get("Authorization")
	if !strings.HasPrefix(value, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(value, "Bearer "))
}

func truncate(value string, max int) string {
	runes := []rune(value)
	if len(runes) <= max {
		return value
	}
	return string(runes[:max])
}

func writeArtifact(path string, raw []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".policy-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o640); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
