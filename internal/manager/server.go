package manager

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
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
	"github.com/Fhwang0926/m-waf/internal/model"
	"github.com/Fhwang0926/m-waf/internal/packages"
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
	downloadLimiter  *requestLimiter
	policySyncMu     sync.Mutex
	policySyncSignal chan struct{}
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
	templates, err := template.ParseFS(webassets.Assets, "templates/*.html")
	if err != nil {
		return nil, err
	}
	catalog, catalogErr := packages.Load(cfg.BundleRoot, cfg.BundlePublicKey, version.Commit, cfg.BundleAllowUnsigned)
	return &Server{
		cfg: cfg, store: store, catalog: catalog, catalogErr: catalogErr, ca: ca, policySigner: policySigner, policyCatalog: policyCatalog, templates: templates,
		sessions: newSessionManager(cfg.SessionKey), loginLimiter: newLoginLimiter(),
		bootstrapLimiter: newRequestLimiter(60, time.Minute), downloadLimiter: newRequestLimiter(8, time.Minute), logger: logger,
		policySyncSignal: make(chan struct{}, 1),
	}, nil
}

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
	return s.store.SyncCatalog(ctx, s.catalog)
}

func (s *Server) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	staticFS, _ := fs.Sub(webassets.Assets, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(staticFS)))
	mux.HandleFunc("GET /health/live", s.live)
	mux.HandleFunc("GET /health/ready", s.ready)
	mux.HandleFunc("GET /setup", s.setup)
	mux.HandleFunc("POST /setup", s.setup)
	mux.HandleFunc("GET /login", s.login)
	mux.HandleFunc("POST /login", s.login)
	mux.Handle("POST /logout", s.requireAdmin(http.HandlerFunc(s.logout)))
	mux.Handle("GET /account", s.requireAdmin(http.HandlerFunc(s.account)))
	mux.Handle("POST /account/password", s.requireAdmin(http.HandlerFunc(s.updateOwnPassword)))
	mux.Handle("GET /", s.requireAdmin(http.HandlerFunc(s.dashboard)))
	mux.Handle("GET /servers", s.requireAdmin(http.HandlerFunc(s.servers)))
	mux.Handle("POST /servers/{id}/commands", s.requireAdmin(s.requireRole(RoleEnterpriseUser, http.HandlerFunc(s.createServerCommand))))
	mux.Handle("POST /servers/{id}/packages", s.requireAdmin(s.requireRole(RoleEnterpriseUser, http.HandlerFunc(s.deployServerPackages))))
	mux.Handle("POST /servers/{id}/revoke", s.requireAdmin(s.requireRole(RoleEnterpriseUser, http.HandlerFunc(s.revokeServer))))
	mux.Handle("GET /events", s.requireAdmin(http.HandlerFunc(s.events)))
	mux.Handle("GET /policies", s.requireAdmin(s.requireRole(RoleEnterpriseUser, http.HandlerFunc(s.policies))))
	mux.Handle("GET /policies/new", s.requireAdmin(s.requireRole(RoleEnterpriseUser, http.HandlerFunc(s.newPolicy))))
	mux.Handle("POST /policies", s.requireAdmin(s.requireRole(RoleEnterpriseUser, http.HandlerFunc(s.createPolicy))))
	mux.Handle("GET /policies/{id}", s.requireAdmin(s.requireRole(RoleEnterpriseUser, http.HandlerFunc(s.enterprisePolicyDetail))))
	mux.Handle("POST /policies/{id}/strategy", s.requireAdmin(s.requireRole(RoleEnterpriseUser, http.HandlerFunc(s.updateEnterprisePolicyStrategy))))
	mux.Handle("POST /policies/{id}/convert", s.requireAdmin(s.requireRole(RoleEnterpriseUser, http.HandlerFunc(s.convertLegacyEnterprisePolicy))))
	mux.Handle("POST /policies/{id}/rollback", s.requireAdmin(s.requireRole(RoleEnterpriseUser, http.HandlerFunc(s.rollbackEnterprisePolicy))))
	mux.Handle("POST /policies/{id}/rollouts/{rollout_id}/approve", s.requireAdmin(s.requireRole(RoleEnterpriseUser, http.HandlerFunc(s.approveEnterprisePolicyRollout))))
	mux.Handle("POST /policies/{id}/rollouts/{rollout_id}/retry", s.requireAdmin(s.requireRole(RoleEnterpriseUser, http.HandlerFunc(s.retryEnterprisePolicyRollout))))
	mux.Handle("GET /system-policies", s.requireAdmin(s.requireRole(RoleSystemAdmin, http.HandlerFunc(s.systemPolicies))))
	mux.Handle("GET /groups", s.requireAdmin(s.requireRole(RoleEnterpriseUser, http.HandlerFunc(s.groups))))
	mux.Handle("POST /groups", s.requireAdmin(s.requireRole(RoleEnterpriseUser, http.HandlerFunc(s.createGroup))))
	mux.Handle("POST /groups/{id}", s.requireAdmin(s.requireRole(RoleEnterpriseUser, http.HandlerFunc(s.updateGroup))))
	mux.Handle("POST /groups/{id}/delete", s.requireAdmin(s.requireRole(RoleEnterpriseUser, http.HandlerFunc(s.deleteGroup))))
	mux.Handle("GET /enrollments/new", s.requireAdmin(s.requireRole(RoleEnterpriseUser, http.HandlerFunc(s.newEnrollment))))
	mux.Handle("POST /enrollments", s.requireAdmin(s.requireRole(RoleEnterpriseUser, http.HandlerFunc(s.createEnrollment))))
	mux.Handle("GET /enterprises", s.requireAdmin(s.requireRole(RoleSystemAdmin, http.HandlerFunc(s.enterprises))))
	mux.Handle("POST /enterprises", s.requireAdmin(s.requireRole(RoleSystemAdmin, http.HandlerFunc(s.createEnterprise))))
	mux.Handle("GET /settings", s.requireAdmin(s.requireRole(RoleSystemAdmin, http.HandlerFunc(s.systemSettings))))
	mux.Handle("POST /settings", s.requireAdmin(s.requireRole(RoleSystemAdmin, http.HandlerFunc(s.updateSystemSettings))))
	mux.Handle("GET /users", s.requireAdmin(s.requireRole(RoleEnterpriseAdmin, http.HandlerFunc(s.users))))
	mux.Handle("POST /users", s.requireAdmin(s.requireRole(RoleEnterpriseAdmin, http.HandlerFunc(s.createUser))))
	mux.Handle("GET /users/{id}", s.requireAdmin(s.requireRole(RoleEnterpriseAdmin, http.HandlerFunc(s.editUser))))
	mux.Handle("POST /users/{id}", s.requireAdmin(s.requireRole(RoleEnterpriseAdmin, http.HandlerFunc(s.updateUser))))
	mux.Handle("POST /users/{id}/delete", s.requireAdmin(s.requireRole(RoleEnterpriseAdmin, http.HandlerFunc(s.deleteUser))))
	mux.Handle("GET /api/v1/servers", s.requireAdmin(http.HandlerFunc(s.apiServers)))
	mux.Handle("GET /api/v1/events", s.requireAdmin(http.HandlerFunc(s.apiEvents)))
	mux.Handle("POST /api/v1/enrollment-tokens", s.requireAdmin(s.requireRole(RoleEnterpriseUser, http.HandlerFunc(s.apiCreateEnrollment))))
	return s.securityHeaders(s.requestLog(mux))
}

func (s *Server) AgentHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", s.live)
	mux.HandleFunc("GET /health/ready", s.ready)
	mux.Handle("GET /bootstrap/v1/install.sh", s.limitBootstrap(http.HandlerFunc(s.bootstrapInstaller)))
	mux.Handle("POST /bootstrap/v1/packages/resolve", s.limitBootstrap(http.HandlerFunc(s.resolvePackages)))
	mux.HandleFunc("GET /bootstrap/v1/packages/{id}", s.bootstrapPackage)
	mux.Handle("GET /packages/v1/keys", s.limitBootstrap(http.HandlerFunc(s.packagePublicKey)))
	mux.Handle("POST /agent/v1/enroll", s.limitBootstrap(http.HandlerFunc(s.enroll)))
	mux.Handle("POST /agent/v1/heartbeat", s.requireAgent(http.HandlerFunc(s.heartbeat)))
	mux.Handle("POST /agent/v1/certificate/renew", s.requireAgent(http.HandlerFunc(s.renewCertificate)))
	mux.Handle("GET /agent/v1/desired-state", s.requireAgent(http.HandlerFunc(s.desiredState)))
	mux.Handle("GET /agent/v1/policy-key", s.requireAgent(http.HandlerFunc(s.policyPublicKey)))
	mux.Handle("GET /agent/v1/artifacts/{id}", s.requireAgent(http.HandlerFunc(s.policyArtifact)))
	mux.Handle("GET /agent/v1/packages/{id}", s.requireAgent(http.HandlerFunc(s.agentPackage)))
	mux.Handle("POST /agent/v1/events/batch", s.requireAgent(http.HandlerFunc(s.eventBatch)))
	mux.Handle("POST /agent/v1/policies/{id}/result", s.requireAgent(http.HandlerFunc(s.policyResult)))
	mux.Handle("POST /agent/v1/package-deployments/{id}/result", s.requireAgent(http.HandlerFunc(s.packageDeploymentResult)))
	mux.Handle("GET /agent/v1/commands/next", s.requireAgent(http.HandlerFunc(s.nextAgentCommand)))
	mux.Handle("POST /agent/v1/commands/{id}/result", s.requireAgent(http.HandlerFunc(s.agentCommandResult)))
	return s.securityHeaders(s.requestLog(mux))
}

func (s *Server) AgentTLSConfig() (*tls.Config, error) {
	certPEM, err := os.ReadFile(s.cfg.AgentCACertificate)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		return nil, errors.New("append agent CA certificate")
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientAuth: tls.VerifyClientCertIfGiven,
		ClientCAs:  pool,
		NextProtos: []string{"h2", "http/1.1"},
	}, nil
}

func (s *Server) live(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "live", "version": version.Version, "commit": version.Commit})
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
			http.Error(w, "load administrator configuration", http.StatusInternalServerError)
			return
		}
		if !hasUsers {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}
		_ = s.templates.ExecuteTemplate(w, "login.html", map[string]any{"PasswordChanged": r.URL.Query().Get("password_changed") == "1"})
		return
	}
	remote := remoteIP(r)
	if !s.loginLimiter.allow(remote) {
		http.Error(w, "too many login attempts", http.StatusTooManyRequests)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	user, err := s.store.UserByUsername(r.Context(), username)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "login unavailable", http.StatusInternalServerError)
		return
	}
	if err != nil || !user.Active || !verifyPassword(r.FormValue("password"), user.PasswordHash) {
		s.loginLimiter.fail(remote)
		w.WriteHeader(http.StatusUnauthorized)
		_ = s.templates.ExecuteTemplate(w, "login.html", map[string]any{"Error": "로그인 정보가 올바르지 않습니다."})
		return
	}
	s.loginLimiter.reset(remote)
	token, data, err := s.sessions.create(user)
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	s.store.RecordLogin(r.Context(), user.ID)
	setSessionCookie(w, token, time.Unix(data.ExpiresAt, 0))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		http.Error(w, "invalid csrf token", http.StatusForbidden)
		return
	}
	clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	session := sessionFrom(r)
	servers, err := s.store.ListServers(r.Context(), session.ScopeEnterpriseID(), 10)
	if err != nil {
		http.Error(w, "load servers", http.StatusInternalServerError)
		return
	}
	events, err := s.store.ListEvents(r.Context(), session.ScopeEnterpriseID(), 10)
	if err != nil {
		http.Error(w, "load events", http.StatusInternalServerError)
		return
	}
	bundleVersion := "unavailable"
	if s.catalog != nil {
		bundleVersion = s.catalog.Manifest().BundleVersion
	}
	data := s.viewData(r, "dashboard", map[string]any{"Servers": servers, "Events": events, "BundleVersion": bundleVersion, "Ready": s.catalog != nil})
	if s.catalogErr != nil {
		data["Notice"] = "Package bundle을 사용할 수 없습니다: " + s.catalogErr.Error()
	}
	_ = s.templates.ExecuteTemplate(w, "dashboard.html", data)
}

func (s *Server) servers(w http.ResponseWriter, r *http.Request) {
	session := sessionFrom(r)
	items, err := s.store.ListServers(r.Context(), session.ScopeEnterpriseID(), 500)
	if err != nil {
		http.Error(w, "load servers", http.StatusInternalServerError)
		return
	}
	if s.catalog != nil {
		for i := range items {
			_, _, rollbackErr := s.catalog.Rollback(items[i].AgentPackageID, items[i].ModulePackageID)
			items[i].CanRollbackPackages = rollbackErr == nil
		}
	}
	_ = s.templates.ExecuteTemplate(w, "servers.html", s.viewData(r, "servers", map[string]any{"Servers": items, "Notice": strings.TrimSpace(r.URL.Query().Get("notice"))}))
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	session := sessionFrom(r)
	filter := EventFilter{ServerID: truncate(strings.TrimSpace(r.URL.Query().Get("server")), 64), Severity: strings.TrimSpace(r.URL.Query().Get("severity")), Query: truncate(strings.TrimSpace(r.URL.Query().Get("q")), 255)}
	if len(filter.Severity) != 1 || filter.Severity[0] < '0' || filter.Severity[0] > '7' {
		filter.Severity = ""
	}
	switch r.URL.Query().Get("result") {
	case "blocked":
		value := true
		filter.Blocked = &value
	case "detected":
		value := false
		filter.Blocked = &value
	}
	page, err := strconv.Atoi(r.URL.Query().Get("page"))
	if err != nil || page < 1 {
		page = 1
	} else if page > 10000 {
		page = 10000
	}
	const pageSize = 100
	filter.Offset = (page - 1) * pageSize
	items, err := s.store.ListEventsFiltered(r.Context(), session.ScopeEnterpriseID(), filter, pageSize+1)
	if err != nil {
		http.Error(w, "load events", http.StatusInternalServerError)
		return
	}
	hasNext := len(items) > pageSize
	if hasNext {
		items = items[:pageSize]
	}
	servers, err := s.store.ListServers(r.Context(), session.ScopeEnterpriseID(), 500)
	if err != nil {
		http.Error(w, "load servers", http.StatusInternalServerError)
		return
	}
	query := r.URL.Query()
	query.Del("page")
	pageURL := func(target int) string {
		values := url.Values{}
		for key, entries := range query {
			for _, entry := range entries {
				values.Add(key, entry)
			}
		}
		values.Set("page", strconv.Itoa(target))
		return "/events?" + values.Encode()
	}
	data := map[string]any{"Events": items, "Servers": servers, "FilterServer": filter.ServerID, "FilterSeverity": filter.Severity, "FilterQuery": filter.Query, "FilterResult": r.URL.Query().Get("result"), "Page": page, "HasNext": hasNext}
	if page > 1 {
		data["PreviousURL"] = pageURL(page - 1)
	}
	if hasNext {
		data["NextURL"] = pageURL(page + 1)
	}
	_ = s.templates.ExecuteTemplate(w, "events.html", s.viewData(r, "events", data))
}

func (s *Server) policies(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListEnterprisePolicies(r.Context(), sessionFrom(r).ScopeEnterpriseID(), 500)
	if err != nil {
		http.Error(w, "load policies", http.StatusInternalServerError)
		return
	}
	_ = s.templates.ExecuteTemplate(w, "policies.html", s.viewData(r, "policies", map[string]any{"Policies": items}))
}

func (s *Server) newPolicy(w http.ResponseWriter, r *http.Request) {
	session := sessionFrom(r)
	servers, err := s.store.ListServers(r.Context(), session.ScopeEnterpriseID(), 500)
	if err != nil {
		http.Error(w, "load servers", http.StatusInternalServerError)
		return
	}
	groups, err := s.store.ListGroups(r.Context(), session.ScopeEnterpriseID())
	if err != nil {
		http.Error(w, "load server groups", http.StatusInternalServerError)
		return
	}
	_ = s.templates.ExecuteTemplate(w, "policy.html", s.viewData(r, "policies", map[string]any{
		"Servers": servers, "Groups": groups, "PolicyTemplates": s.policyCatalog.ListLatest(), "DefaultTemplate": s.policyCatalog.Default(),
	}))
}

func (s *Server) createPolicy(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		http.Error(w, "invalid csrf token", http.StatusForbidden)
		return
	}
	name := truncate(strings.TrimSpace(r.FormValue("name")), 255)
	description := truncate(strings.TrimSpace(r.FormValue("description")), 1024)
	target := strings.TrimSpace(r.FormValue("target"))
	templateKey := strings.TrimSpace(r.FormValue("template_key"))
	if templateKey == "" {
		templateKey = s.policyCatalog.Default().Key
	}
	policyTemplate, ok := s.policyCatalog.Latest(templateKey)
	if !ok {
		http.Error(w, "지원하지 않는 시스템 정책 템플릿입니다.", http.StatusBadRequest)
		return
	}
	mode := strings.TrimSpace(r.FormValue("mode"))
	paranoiaLevel, paranoiaErr := strconv.Atoi(strings.TrimSpace(r.FormValue("paranoia_level")))
	inboundScore, scoreErr := strconv.Atoi(strings.TrimSpace(r.FormValue("inbound_score")))
	if name == "" || target == "" || paranoiaErr != nil || scoreErr != nil {
		http.Error(w, "정책 이름, 대상과 유효한 세부 설정이 필요합니다.", http.StatusBadRequest)
		return
	}
	strategy := strings.TrimSpace(r.FormValue("update_strategy"))
	if strategy == "" {
		strategy = PolicyStrategyManual
	}
	if strategy != PolicyStrategyManual && strategy != PolicyStrategyAutomatic && strategy != PolicyStrategyPinned {
		http.Error(w, "지원하지 않는 업데이트 전략입니다.", http.StatusBadRequest)
		return
	}
	metadata := ManagedPolicyMetadata{
		SchemaVersion: policyTemplate.SchemaVersion, TemplateKey: policyTemplate.Key, TemplateVersion: policyTemplate.Version,
		CRSTrack: policyTemplate.CRSTrack, CRSVersion: policyTemplate.CRSVersion, Target: target,
		AutoUpdate: strategy == PolicyStrategyAutomatic, PolicyOrigin: "administrator", MigrationStatus: "CURRENT",
	}
	artifact, settingsJSON, err := buildManagedPolicyArtifact(mode, paranoiaLevel, inboundScore, r.FormValue("request_body") == "on", r.FormValue("excluded_paths"), r.FormValue("excluded_ips"), r.FormValue("custom_rules"), metadata)
	if err != nil {
		http.Error(w, "정책 설정이 올바르지 않습니다: "+err.Error(), http.StatusBadRequest)
		return
	}
	session := sessionFrom(r)
	enterpriseID, serverIDs, err := s.store.ResolvePolicyTarget(r.Context(), session.ScopeEnterpriseID(), target)
	if err != nil {
		http.Error(w, "정책 대상을 찾을 수 없습니다: "+err.Error(), http.StatusBadRequest)
		return
	}
	servers, err := s.store.ListServers(r.Context(), enterpriseID, systemPolicyServerLimit)
	if err != nil {
		http.Error(w, "load policy target servers", http.StatusInternalServerError)
		return
	}
	policyID := randomID()
	existingPolicies, err := s.store.ListEnterprisePolicies(r.Context(), enterpriseID, systemPolicyServerLimit)
	if err != nil {
		http.Error(w, "load enterprise policies", http.StatusInternalServerError)
		return
	}
	candidate := EnterprisePolicyRecord{ID: policyID, EnterpriseID: enterpriseID, Target: target, Status: EnterprisePolicyActive, CurrentRevisionID: "candidate", UpdatedAt: time.Now().UTC()}
	winners, err := s.enterprisePolicyWinners(r.Context(), append(existingPolicies, candidate), servers)
	if err != nil {
		http.Error(w, "resolve policy priority", http.StatusInternalServerError)
		return
	}
	serverIDs = orderIDsByServers(winners[policyID], servers)
	if len(serverIDs) == 0 {
		http.Error(w, "정책 대상에 적용 가능한 서버가 없습니다.", http.StatusBadRequest)
		return
	}
	revisionID := randomID()
	hash, signature := s.policySigner.Sign(artifact)
	relativePath := filepath.Join("policies", revisionID+".conf")
	fullPath := filepath.Join(s.cfg.ArtifactRoot, relativePath)
	if err := writeArtifact(fullPath, artifact); err != nil {
		http.Error(w, "write policy artifact", http.StatusInternalServerError)
		return
	}
	revision := PolicyRevisionInput{
		ID: revisionID, SystemPolicyVersionID: policyTemplate.Reference(), Name: name, Description: description, Mode: mode,
		SettingsJSON: settingsJSON, ArtifactPath: filepath.ToSlash(relativePath), ArtifactSHA256: hash, ArtifactSignature: signature, PolicyOrigin: "administrator",
	}
	rolloutID, err := s.store.CreateEnterprisePolicyWithRollout(r.Context(), enterpriseID, policyID, name, description, target, policyTemplate.Key, strategy, session.UserID, revision, "SEED", "QUEUED", serverIDs)
	if err != nil {
		_ = os.Remove(fullPath)
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "server not found", http.StatusNotFound)
			return
		}
		http.Error(w, "create enterprise policy", http.StatusInternalServerError)
		return
	}
	s.audit(r, session.Username, "enterprise_policy.create", policyID+":"+rolloutID, "success")
	s.TriggerPolicySync()
	http.Redirect(w, r, "/policies/"+policyID+"?notice="+url.QueryEscape("기업 정책이 "+strconv.Itoa(len(serverIDs))+"대 서버에 단계 배포 대기 중입니다."), http.StatusSeeOther)
}

func (s *Server) newEnrollment(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{}
	if sessionFrom(r).IsSystemAdmin() {
		enterprises, err := s.store.ListEnterprises(r.Context())
		if err != nil {
			http.Error(w, "load enterprises", http.StatusInternalServerError)
			return
		}
		data["Enterprises"] = enterprises
	}
	_ = s.templates.ExecuteTemplate(w, "enrollment.html", s.viewData(r, "enrollments", data))
}

func (s *Server) createEnrollment(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		http.Error(w, "invalid csrf token", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	label := truncate(strings.TrimSpace(r.FormValue("label")), 255)
	if label == "" {
		http.Error(w, "label is required", http.StatusBadRequest)
		return
	}
	enterpriseID, ok := s.requestEnterpriseID(r)
	if !ok {
		http.Error(w, "valid enterprise is required", http.StatusBadRequest)
		return
	}
	token, expires, err := s.store.CreateEnrollmentToken(r.Context(), enterpriseID, label, s.cfg.EnrollmentTTL)
	if err != nil {
		http.Error(w, "create enrollment", http.StatusInternalServerError)
		return
	}
	s.audit(r, sessionFrom(r).Username, "enrollment.create", label, "success")
	_ = s.templates.ExecuteTemplate(w, "enrollment.html", s.viewData(r, "enrollments", map[string]any{"Token": token, "ExpiresAt": expires, "AgentURL": s.cfg.AgentPublicURL}))
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
	items, err := s.store.ListEvents(r.Context(), sessionFrom(r).ScopeEnterpriseID(), 500)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "load events")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
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
	writeJSON(w, http.StatusCreated, map[string]any{"token": token, "expires_at": expires, "agent_api": s.cfg.AgentPublicURL})
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
	agent, module, err := s.catalog.Resolve(request.Inventory)
	if err != nil {
		writeProblem(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if err := s.store.AllowEnrollmentPackages(r.Context(), request.Token, []string{agent.ID, module.ID}); err != nil {
		writeProblem(w, http.StatusUnauthorized, "invalid enrollment token")
		return
	}
	expires := time.Now().UTC().Add(s.cfg.EnrollmentTTL)
	resolution := model.PackageResolution{
		BundleVersion: s.catalog.Manifest().BundleVersion,
		ExpiresAt:     expires,
		Agent:         packageDownload(s.cfg.AgentPublicURL, agent),
		Module:        packageDownload(s.cfg.AgentPublicURL, module),
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
	writeJSON(w, http.StatusCreated, model.EnrollResponse{ServerID: serverID, CertificatePEM: certificate, CACertificate: s.ca.CertificatePEM(), PolicyPublicKey: s.policySigner.PublicPEM(), AgentAPI: s.cfg.AgentPublicURL})
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
		state.ArtifactURL = "/agent/v1/artifacts/" + state.RevisionID
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
		event.Message = truncate(event.Message, 2048)
		event.RuleID = truncate(event.RuleID, 64)
	}
	duplicate, err := s.store.InsertEventBatch(r.Context(), agentIDFrom(r), batch)
	if err != nil {
		w.Header().Set("Retry-After", "5")
		writeProblem(w, http.StatusServiceUnavailable, "event storage unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"accepted": true, "duplicate": duplicate, "count": len(batch.Events)})
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
		data.EnterpriseID = user.EnterpriseID
		data.EnterpriseName = user.EnterpriseName
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), contextSession, data)))
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
	return model.PackageDownload{ID: artifact.ID, Name: artifact.Name, Version: artifact.Version, URL: base + "/bootstrap/v1/packages/" + artifact.ID, Size: artifact.Size, SHA256: artifact.SHA256, RollbackID: artifact.RollbackID}
}

func agentPackageDownload(artifact model.PackageArtifact) model.PackageDownload {
	return model.PackageDownload{ID: artifact.ID, Name: artifact.Name, Version: artifact.Version, URL: "/agent/v1/packages/" + artifact.ID, Size: artifact.Size, SHA256: artifact.SHA256, RollbackID: artifact.RollbackID}
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
