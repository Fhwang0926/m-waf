package manager

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/Fhwang0926/m-waf/internal/model"
	webassets "github.com/Fhwang0926/m-waf/web"
)

func TestAdminStatusLabels(t *testing.T) {
	cases := map[string]string{
		"ONLINE":            "온라인",
		"OFFLINE":           "오프라인",
		"APPLIED":           "적용 완료",
		"FAILED":            "실패",
		"AWAITING_APPROVAL": "승인 대기",
		"CANARY":            "카나리 적용",
		"EXPANDING":         "확대 배포",
	}
	for status, expected := range cases {
		if actual := statusLabel(status); actual != expected {
			t.Fatalf("statusLabel(%q) = %q, want %q", status, actual, expected)
		}
	}
}

func TestNavigationVisibilityByRole(t *testing.T) {
	templates, err := webassets.ParseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	render := func(role Role, activeValues ...string) string {
		t.Helper()
		active := "dashboard"
		if len(activeValues) != 0 {
			active = activeValues[0]
		}
		session := sessionData{DisplayName: "Operator", Role: role, ActualRole: role, EnterpriseID: "enterprise-a", EnterpriseName: "Example"}
		systemArea := map[string]bool{"enterprises": true, "open-source-policies": true, "system-policies": true, "audit-logs": true, "settings": true}
		if role == RoleSystemAdmin && systemArea[active] {
			session = session.asSystemConsole()
		} else {
			session = session.asEnterpriseConsole()
		}
		data := map[string]any{
			"Active": active, "Session": session, "CSRF": "token",
			"IsSystemAdmin": session.IsSystemAdmin(), "CanAccessSystemManagement": session.CanAccessSystemManagement(), "InSystemConsole": session.InSystemConsole(),
			"CanOperate": session.CanOperate(), "CanManageUsers": session.CanManageUsers(), "AccountURL": "/account",
		}
		var output bytes.Buffer
		if err := templates.ExecuteTemplate(&output, "navigation", data); err != nil {
			t.Fatal(err)
		}
		return output.String()
	}

	system := render(RoleSystemAdmin)
	for _, label := range []string{"운영 현황", "보안 이벤트", "보고서", "보호 정책", "사용자 정책", "보호 서버", "서버 설치", "사용자 관리", "기업 관리", "CRS 관리", "시스템 정책", "감사 로그", "시스템 설정"} {
		if !strings.Contains(system, label) {
			t.Fatalf("system administrator navigation is missing %q: %s", label, system)
		}
	}
	if !strings.Contains(system, "현재 권한") || !strings.Contains(system, "<strong>기업 관리자</strong>") || !strings.Contains(system, "Example 관리 콘솔") {
		t.Fatalf("enterprise console does not expose the projected role and enterprise: %s", system)
	}
	triggerStart := strings.Index(system, `<summary aria-label="계정 메뉴">`)
	if triggerStart < 0 {
		t.Fatalf("account menu trigger is missing: %s", system)
	}
	triggerEnd := strings.Index(system[triggerStart:], `</summary>`)
	if triggerEnd < 0 {
		t.Fatalf("account menu trigger is missing: %s", system)
	}
	trigger := system[triggerStart : triggerStart+triggerEnd]
	if strings.Contains(trigger, "시스템 관리자") || strings.Contains(trigger, "Example") {
		t.Fatalf("role or enterprise must only appear inside the account dropdown: %s", trigger)
	}
	if strings.Contains(system, "그룹 정책 대상") || strings.Contains(system, "설치 및 등록") {
		t.Fatalf("system administrator navigation is incomplete: %s", system)
	}
	crsNavigation := render(RoleSystemAdmin, "open-source-policies")
	if !strings.Contains(crsNavigation, `class="side-link active" href="/open-source-policies"`) || strings.Contains(crsNavigation, `class="side-link active" href="/system-policies"`) {
		t.Fatalf("CRS management navigation is not independently active: %s", crsNavigation)
	}
	if !strings.Contains(crsNavigation, "<strong>시스템 관리자</strong>") || !strings.Contains(crsNavigation, "시스템 관리 콘솔") {
		t.Fatalf("system console does not expose the actual system role: %s", crsNavigation)
	}
	systemPolicyNavigation := render(RoleSystemAdmin, "system-policies")
	if !strings.Contains(systemPolicyNavigation, `class="side-link active" href="/system-policies"`) || strings.Contains(systemPolicyNavigation, `class="side-link active" href="/open-source-policies"`) {
		t.Fatalf("system policy navigation is not independently active: %s", systemPolicyNavigation)
	}
	serverInstallNavigation := render(RoleSystemAdmin, "enrollments")
	if !strings.Contains(serverInstallNavigation, `class="side-link active" href="/enrollments/new"`) || strings.Contains(serverInstallNavigation, `class="side-link active" href="/servers"`) {
		t.Fatalf("server install navigation is not independently active: %s", serverInstallNavigation)
	}
	admin := render(RoleEnterpriseAdmin)
	if strings.Contains(admin, "CRS 관리") || strings.Contains(admin, "시스템 정책") || strings.Contains(admin, "시스템 설정") || !strings.Contains(admin, "사용자 관리") || !strings.Contains(admin, "사용자 정책") || !strings.Contains(admin, "서버 설치") {
		t.Fatalf("enterprise administrator navigation is incorrect: %s", admin)
	}
	user := render(RoleEnterpriseUser)
	if strings.Contains(user, "CRS 관리") || strings.Contains(user, "시스템 정책") || strings.Contains(user, "시스템 설정") || strings.Contains(user, "사용자 관리") || !strings.Contains(user, "보호 정책") || !strings.Contains(user, "사용자 정책") || !strings.Contains(user, "서버 설치") {
		t.Fatalf("enterprise user navigation exposes restricted menus: %s", user)
	}
	if !strings.Contains(user, `class="side-link active" href="/"`) {
		t.Fatalf("dashboard navigation is not active: %s", user)
	}
	reports := render(RoleEnterpriseUser, "reports")
	if !strings.Contains(reports, `class="side-link active" href="/reports"`) || strings.Contains(reports, `class="side-link active" href="/events"`) {
		t.Fatalf("report navigation is not independently active: %s", reports)
	}
}

func TestSystemEnterpriseUsersStayInSystemManagement(t *testing.T) {
	templates, err := webassets.ParseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	session := sessionData{DisplayName: "Operator", Role: RoleSystemAdmin, ActualRole: RoleSystemAdmin, EnterpriseID: "system-enterprise", EnterpriseName: "System"}.asSystemConsole()
	data := map[string]any{
		"Active": "enterprises", "Session": session, "CSRF": "token", "ScopeLabel": "전체 기업",
		"IsSystemAdmin": true, "CanAccessSystemManagement": true, "InSystemConsole": true, "CanOperate": true, "CanManageUsers": true,
		"AccountURL": "/account?area=system", "Enterprise": EnterpriseRecord{ID: "enterprise-a", Name: "Example", Status: "ACTIVE"},
		"Users":     []UserRecord{{ID: "user-a", EnterpriseID: "enterprise-a", Username: "admin", DisplayName: "Admin", Role: RoleEnterpriseAdmin, Active: true, Manageable: true}},
		"UserTotal": 1, "UserBaseURL": "/enterprises/enterprise-a/users",
	}
	var output bytes.Buffer
	if err := templates.ExecuteTemplate(&output, "enterprise-users.html", data); err != nil {
		t.Fatal(err)
	}
	html := output.String()
	if !strings.Contains(html, `action="/enterprises/enterprise-a/users"`) || !strings.Contains(html, `href="/enterprises/enterprise-a/users/user-a"`) {
		t.Fatalf("system enterprise user routes are missing: %s", html)
	}
	if strings.Contains(html, `href="/users/user-a"`) || !strings.Contains(html, "시스템 관리 · 기업 사용자") {
		t.Fatalf("enterprise operation user route leaked into system management: %s", html)
	}
}

func TestSystemPolicyAdoptionsStayReadOnly(t *testing.T) {
	templates, err := webassets.ParseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	session := sessionData{DisplayName: "Operator", Role: RoleSystemAdmin, ActualRole: RoleSystemAdmin, EnterpriseID: "system-enterprise", EnterpriseName: "System"}.asSystemConsole()
	data := map[string]any{
		"Active": "system-policies", "Session": session, "CSRF": "token", "ScopeLabel": "전체 기업",
		"IsSystemAdmin": true, "CanAccessSystemManagement": true, "InSystemConsole": true, "CanOperate": true, "CanManageUsers": true,
		"AccountURL": "/account?area=system", "Policy": SystemPolicyVersionRecord{ID: "system-policy-a", CRSVersion: "4.25.1", Status: "PUBLISHED"},
		"Policies": []EnterprisePolicyRecord{{ID: "policy-a", EnterpriseID: "enterprise-a", EnterpriseName: "Example", Name: "Default", Target: "enterprise:enterprise-a", CurrentMode: "DetectionOnly", UpdateStrategy: PolicyStrategyManual, LatestRolloutStatus: "APPLIED"}},
	}
	var output bytes.Buffer
	if err := templates.ExecuteTemplate(&output, "system-policy-adoptions.html", data); err != nil {
		t.Fatal(err)
	}
	html := output.String()
	if !strings.Contains(html, "읽기 전용") || !strings.Contains(html, `href="/enterprises/enterprise-a"`) {
		t.Fatalf("system policy adoption view is incomplete: %s", html)
	}
	if strings.Contains(html, `href="/policies/policy-a"`) || strings.Contains(html, `action="/policies/`) {
		t.Fatalf("enterprise operation action leaked into system policy view: %s", html)
	}
	if !strings.Contains(html, "각 기업 사용자 또는 기업 관리자") {
		t.Fatalf("enterprise policy operator guidance is missing: %s", html)
	}
}

func TestSystemPolicyOverviewDoesNotLinkEnterpriseOperations(t *testing.T) {
	templates, err := webassets.ParseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	session := sessionData{DisplayName: "Operator", Role: RoleSystemAdmin, ActualRole: RoleSystemAdmin, EnterpriseID: "system-enterprise", EnterpriseName: "System"}.asSystemConsole()
	data := map[string]any{
		"Active": "system-policies", "Session": session, "CSRF": "token", "ScopeLabel": "전체 기업",
		"IsSystemAdmin": true, "CanAccessSystemManagement": true, "InSystemConsole": true, "CanOperate": true, "CanManageUsers": true,
		"AccountURL": "/account?area=system", "Summary": systemPolicyOperationsSummary{PendingUpdateCount: 2, ActiveRolloutCount: 1},
		"Lifecycle": systemPolicyLifecycleView{}, "PublishedResult": systemPolicyPublishedResult{}, "Tab": "policies",
	}
	var output bytes.Buffer
	if err := templates.ExecuteTemplate(&output, "system-policies.html", data); err != nil {
		t.Fatal(err)
	}
	html := output.String()
	if !strings.Contains(html, "읽기 전용으로 확인") || !strings.Contains(html, "기업별 검토 대기") {
		t.Fatalf("read-only system policy guidance is incomplete: %s", html)
	}
	mainStart := strings.Index(html, "<main")
	if mainStart < 0 {
		t.Fatalf("system policy main content is missing: %s", html)
	}
	mainHTML := html[mainStart:]
	if strings.Contains(mainHTML, `href="/policies`) || strings.Contains(mainHTML, "기업 정책 조치 보기") || strings.Contains(mainHTML, "승인 대기 보기") {
		t.Fatalf("enterprise operation action leaked into system policy overview: %s", html)
	}
}

func TestEnterpriseDetailTabSelection(t *testing.T) {
	cases := map[string]string{
		"":           "overview",
		"overview":   "overview",
		" USERS ":    "users",
		"servers":    "servers",
		"policies":   "policies",
		"groups":     "overview",
		"management": "management",
		"unknown":    "overview",
	}
	for input, expected := range cases {
		if actual := enterpriseDetailTab(input); actual != expected {
			t.Fatalf("enterpriseDetailTab(%q) = %q, want %q", input, actual, expected)
		}
	}
}

func TestServerDetailTabSelection(t *testing.T) {
	cases := map[string]string{
		"":              "status",
		"status":        "status",
		" ENVIRONMENT ": "environment",
		"policies":      "policies",
		"packages":      "packages",
		"commands":      "commands",
		"risk":          "risk",
		"unknown":       "status",
	}
	for input, expected := range cases {
		if actual := serverDetailTab(input); actual != expected {
			t.Fatalf("serverDetailTab(%q) = %q, want %q", input, actual, expected)
		}
	}
}

func TestEnterpriseDetailRendersOnlySelectedTab(t *testing.T) {
	templates, err := webassets.ParseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	session := sessionData{DisplayName: "Operator", Role: RoleSystemAdmin, ActualRole: RoleSystemAdmin, EnterpriseID: "system-enterprise", EnterpriseName: "System"}.asSystemConsole()
	data := map[string]any{
		"Active": "enterprises", "Session": session, "CSRF": "token", "ScopeLabel": "전체 기업",
		"IsSystemAdmin": true, "CanAccessSystemManagement": true, "InSystemConsole": true, "CanOperate": true, "CanManageUsers": true,
		"AccountURL": "/account?area=system", "Enterprise": EnterpriseRecord{ID: "enterprise-a", Name: "Example", Status: "ACTIVE"},
		"Users": []UserRecord{}, "Servers": []ServerRecord{}, "Policies": []EnterprisePolicyRecord{},
	}
	tabs := []string{"overview", "users", "servers", "policies", "management"}
	for _, selected := range tabs {
		data["Tab"] = selected
		var output bytes.Buffer
		if err := templates.ExecuteTemplate(&output, "enterprise-detail.html", data); err != nil {
			t.Fatalf("render %s tab: %v", selected, err)
		}
		html := output.String()
		for _, section := range tabs {
			visible := strings.Contains(html, `id="`+section+`"`)
			if section == selected && !visible {
				t.Fatalf("selected %s section is missing: %s", selected, html)
			}
			if section != selected && visible {
				t.Fatalf("inactive %s section rendered with selected %s: %s", section, selected, html)
			}
		}
		if selected == "overview" && !strings.Contains(html, `aria-label="기업 연결 현황"`) {
			t.Fatalf("overview summary is missing: %s", html)
		}
		if selected != "overview" && strings.Contains(html, `aria-label="기업 연결 현황"`) {
			t.Fatalf("overview summary leaked into %s tab: %s", selected, html)
		}
	}
}

func TestEnrollmentQuickInstallKeepsTokenOutOfCommand(t *testing.T) {
	templates, err := webassets.ParseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	session := sessionData{DisplayName: "Operator", Role: RoleSystemAdmin, ActualRole: RoleSystemAdmin, EnterpriseID: "system-enterprise", EnterpriseName: "System"}.asSystemConsole()
	const installToken = "mwaf_it_example-secret"
	data := map[string]any{
		"Active": "enrollments", "Session": session, "CSRF": "token", "ScopeLabel": "전체 기업",
		"IsSystemAdmin": true, "CanAccessSystemManagement": true, "InSystemConsole": true, "CanOperate": true, "CanManageUsers": true,
		"AccountURL": "/account?area=system", "SelectedEnterpriseID": "enterprise-1", "SelectedEnterpriseName": "Example", "InstallToken": installToken,
		"BootstrapTLSPin": "sha256//example", "BootstrapInstallerSHA256": strings.Repeat("a", 64), "AgentURL": "https://manager.example:10443",
	}
	var output bytes.Buffer
	if err := templates.ExecuteTemplate(&output, "enrollment.html", data); err != nil {
		t.Fatal(err)
	}
	html := output.String()
	for _, expected := range []string{"빠른 설치", "Agent 설치와 자동 등록", "Agent 설치 명령 복사", "별도 입력이 필요하지 않습니다", "보호 서버 상세에서 웹서버와 WAF 모듈 설치", `data-enrollment-command`, `data-enterprise-id="enterprise-1"`, `data-csrf="token"`, `class="install-command-details"`, "__MWAF_ENROLLMENT_TOKEN__", "Debian 12", "Ubuntu 24.04·26.04", "Ubuntu 18.04·20.04·22.04", "Agent + Apache 모듈", "Docker", "환경 자동 감지", "wget --no-check-certificate", "sha256sum -c -", "--bootstrap-pin", "--token-stdin", strings.Repeat("a", 64)} {
		if !strings.Contains(html, expected) {
			t.Fatalf("quick install content %q is missing: %s", expected, html)
		}
	}
	if strings.Contains(html, "install-quick-steps") {
		t.Fatalf("redundant install step cards remain: %s", html)
	}
	if strings.Contains(html, `<p class="eyebrow">1단계</p>`) {
		t.Fatalf("orphaned first-step label remains without an in-page next step: %s", html)
	}
	if strings.Contains(html, "설치 구성") || strings.Contains(html, "Agent + 통합 모듈") {
		t.Fatalf("removed installation composition card remains: %s", html)
	}
	if strings.Contains(html, "curl -k") {
		t.Fatalf("insecure TLS bypass leaked into the install command: %s", html)
	}
	commandStart := strings.Index(html, `id="enterprise-install-command"`)
	if commandStart < 0 {
		t.Fatalf("install command is missing: %s", html)
	}
	commandEnd := strings.Index(html[commandStart:], "</pre>")
	if commandEnd < 0 {
		t.Fatalf("install command closing tag is missing: %s", html)
	}
	commandHTML := html[commandStart : commandStart+commandEnd]
	if strings.Contains(commandHTML, "base64 -d") {
		t.Fatalf("inline CA payload remains in the quick install command: %s", commandHTML)
	}
	for _, removed := range []string{"mwaf_install_dir=", "enrollment.token", "mwaf_root_command", "trap - EXIT"} {
		if strings.Contains(commandHTML, removed) {
			t.Fatalf("removed quick-install boilerplate %q remains: %s", removed, commandHTML)
		}
	}
	if strings.Contains(commandHTML, installToken) {
		t.Fatalf("install token must not be embedded in the copied command")
	}
	if strings.Contains(commandHTML, "--install-token-stdin") {
		t.Fatalf("quick install must not require a second token prompt: %s", commandHTML)
	}
}

func TestBootstrapInstallerInstallsAgentOnlyBeforeManagerPlanning(t *testing.T) {
	raw, err := bootstrapFiles.ReadFile("bootstrap-install.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(raw)
	for _, expected := range []string{
		`-d|--manager) manager=$2`,
		`--token-file) token_file=$2`,
		`--token-stdin) token_stdin=1`,
		`exec sudo sh "$0" "$@"`,
		`--bootstrap-pin) bootstrap_pin=$2`,
		`--pinnedpubkey "$bootstrap_pin"`,
		`/bootstrap/v1/ca.crt`,
		`"installation_mode":"discovery"`,
		`ubuntu:18.04|ubuntu:20.04|ubuntu:22.04|ubuntu:24.04|ubuntu:26.04|debian:12`,
		"This first stage installs no",
		`runtime_mode=container`,
		`/usr/sbin/mwaf-agent-service start`,
		"M-WAF unassigned safe policy",
		"SecRuleEngine DetectionOnly",
		"Select package-based or custom ZIP installation in Manager",
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("bootstrap installer content %q is missing", expected)
		}
	}
	if strings.Contains(script, "systemd systemctl is required") {
		t.Fatal("bootstrap installer still rejects systemd-free containers")
	}
	if strings.Contains(script, "mwaf-agent-container-service") {
		t.Fatal("bootstrap installer exposes the removed container-only service command")
	}
	for _, forbidden := range []string{"a2enconf mwaf", "systemctl reload apache2", "nginx -t", "mwaf-module.deb"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("Agent-only bootstrap must not contain %q", forbidden)
		}
	}
}

func TestBootstrapInstallerSHA256MatchesServedScript(t *testing.T) {
	raw, err := bootstrapFiles.ReadFile("bootstrap-install.sh")
	if err != nil {
		t.Fatal(err)
	}
	actual, err := bootstrapInstallerSHA256()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if expected := hex.EncodeToString(digest[:]); actual != expected {
		t.Fatalf("installer SHA-256 mismatch: got %q want %q", actual, expected)
	}
}

func TestBootstrapInstallerSupportsExistingIdentityAgentUpgrade(t *testing.T) {
	raw, err := bootstrapFiles.ReadFile("bootstrap-install.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(raw)
	for _, expected := range []string{"--upgrade-agent", "/agent/v1/upgrades", "/var/lib/mwaf-agent/agent.crt", "/var/lib/mwaf-agent/agent.key", "existing server ID and mTLS identity were preserved"} {
		if !strings.Contains(script, expected) {
			t.Fatalf("in-place Agent upgrade is missing %q", expected)
		}
	}
}

func TestServerDetailRendersOnlySelectedTab(t *testing.T) {
	templates, err := webassets.ParseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	session := sessionData{DisplayName: "Operator", Role: RoleEnterpriseAdmin, ActualRole: RoleEnterpriseAdmin, EnterpriseID: "enterprise-a", EnterpriseName: "Example"}.asEnterpriseConsole()
	data := map[string]any{
		"Active": "servers", "Session": session, "CSRF": "token", "ScopeLabel": "Example", "CanOperate": true, "CanManageUsers": true,
		"Tab": "environment", "AccountURL": "/account", "Server": ServerRecord{ID: "server-a", EnterpriseName: "Example", Name: "web-a"},
	}
	var output bytes.Buffer
	if err := templates.ExecuteTemplate(&output, "server-detail.html", data); err != nil {
		t.Fatal(err)
	}
	html := output.String()
	if !strings.Contains(html, `<section id="environment"`) || !strings.Contains(html, `href="/servers/server-a?tab=environment" aria-current="page"`) {
		t.Fatalf("selected server environment tab is not rendered: %s", html)
	}
	for _, hidden := range []string{`<section id="status"`, `<section id="policies"`, `<section id="packages"`, `<section id="commands"`, `<section id="risk"`} {
		if strings.Contains(html, hidden) {
			t.Fatalf("unselected server detail section is rendered: %s", hidden)
		}
	}
}

func TestServerDetailStatusShowsSystemSummary(t *testing.T) {
	templates, err := webassets.ParseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	session := sessionData{DisplayName: "Operator", Role: RoleEnterpriseAdmin, ActualRole: RoleEnterpriseAdmin, EnterpriseID: "enterprise-a", EnterpriseName: "Example"}.asEnterpriseConsole()
	data := map[string]any{
		"Active": "servers", "Session": session, "CSRF": "token", "ScopeLabel": "Example", "CanOperate": true, "CanManageUsers": true,
		"Tab": "status", "AccountURL": "/account", "Server": ServerRecord{
			ID: "server-a", EnterpriseName: "Example", Name: "web-a", Status: "ONLINE", EnterprisePolicyID: "policy-a", EnterprisePolicyName: "기본 보호 정책", PolicyDeploymentStatus: "APPLIED",
			Inventory: model.Inventory{OSID: "ubuntu", OSVersion: "18.04", Architecture: "amd64", CPUCoreCount: 8, MemoryTotalBytes: 8 << 30, AgentVersion: "1.0.0"},
		},
	}
	var output bytes.Buffer
	if err := templates.ExecuteTemplate(&output, "server-detail.html", data); err != nil {
		t.Fatal(err)
	}
	html := output.String()
	for _, expected := range []string{"시스템 정보", "서버 플랫폼", "server-system-fact", "server-fact-icon", "/static/brand-ubuntu.png", "Ubuntu 18.04", "amd64", "8 코어", "8.0 GiB", "온라인", "적용 완료", "기본 보호 정책"} {
		if !strings.Contains(html, expected) {
			t.Fatalf("server system summary is missing %q: %s", expected, html)
		}
	}
}

func TestServerDetailSeparatesPackageAndCustomZIPPlans(t *testing.T) {
	templates, err := webassets.ParseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	session := sessionData{DisplayName: "Operator", Role: RoleEnterpriseAdmin, ActualRole: RoleEnterpriseAdmin, EnterpriseID: "enterprise-a", EnterpriseName: "Example"}.asEnterpriseConsole()
	data := map[string]any{
		"Active": "servers", "Session": session, "CSRF": "token", "ScopeLabel": "Example", "CanOperate": true, "CanManageUsers": true, "AgentSelfUpdateReady": true,
		"Tab":        "packages",
		"AccountURL": "/account", "Server": ServerRecord{ID: "server-a", EnterpriseName: "Example", Name: "web-a", Inventory: model.Inventory{AgentVersion: "1.0.0", InstallationStage: model.InstallationStagePlanRequired}},
		"InstallationCandidates": []serverInstallationCandidateView{
			{Kind: "apache", Version: "2.4.58", BuildHash: "apache-build", Binary: "/usr/sbin/apachectl", PackageManaged: true, PackageAvailable: true},
			{Kind: "nginx", Version: "1.24.0", BuildHash: "nginx-build", Binary: "/opt/hosting/nginx/sbin/nginx", CustomZIPAvailable: true},
		},
	}
	var output bytes.Buffer
	if err := templates.ExecuteTemplate(&output, "server-detail.html", data); err != nil {
		t.Fatal(err)
	}
	html := output.String()
	for _, expected := range []string{"Agent 준비", "웹서버 연동", "웹서버 확인과 모듈 설치", `class="package-version-value" title="1.0.0"`, "패키지 기반으로 설치", "커스텀 ZIP으로 설치", "/opt/m-waf", `action="/servers/server-a/installation"`, `name="web_server_control"`, "자동 설정 검사·재적용 (권장)", "사용자 지정 실행 파일 사용 (고급)", "/opt/m-waf/hooks/nginx/configtest", "/opt/m-waf/hooks/nginx/reload"} {
		if !strings.Contains(html, expected) {
			t.Fatalf("server installation plan UI is missing %q: %s", expected, html)
		}
	}
	if strings.Contains(html, "설정 파일을 자동으로 수정") {
		t.Fatalf("server plan UI claims automatic configuration changes: %s", html)
	}
	if strings.Contains(html, `name="custom_command"`) || strings.Contains(html, `name="reload_command"`) {
		t.Fatalf("server plan UI must not accept arbitrary commands: %s", html)
	}
	if strings.Contains(html, "/groups/") || strings.Contains(html, "소속 그룹") {
		t.Fatalf("legacy server group UI remains in server detail: %s", html)
	}
	server := data["Server"].(ServerRecord)
	server.PackageDeploymentStatus = "PENDING"
	data["Server"] = server
	data["AgentUpdateAvailable"] = true
	output.Reset()
	if err := templates.ExecuteTemplate(&output, "server-detail.html", data); err != nil {
		t.Fatal(err)
	}
	html = output.String()
	for _, expected := range []string{"업데이트 예약됨", "Agent 업데이트 예약됨", "Agent 업데이트 완료 후 웹서버 연동을 진행합니다."} {
		if !strings.Contains(html, expected) {
			t.Fatalf("pending Agent update UI is missing %q: %s", expected, html)
		}
	}
	if strings.Contains(html, "업데이트 준비 완료") || strings.Contains(html, "Agent 설치 작업 대기") {
		t.Fatalf("pending Agent update UI contains a conflicting state: %s", html)
	}
}

func TestServerDetailShowsActionableMissingModuleResolution(t *testing.T) {
	templates, err := webassets.ParseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	session := sessionData{DisplayName: "Operator", Role: RoleEnterpriseAdmin, ActualRole: RoleEnterpriseAdmin, EnterpriseID: "enterprise-a", EnterpriseName: "Example"}.asEnterpriseConsole()
	data := map[string]any{
		"Active": "servers", "Session": session, "CSRF": "token", "ScopeLabel": "Example", "CanOperate": true, "AgentSelfUpdateReady": true,
		"Tab": "packages", "AccountURL": "/account", "CurrentPackageAction": serverPackageActionView{Code: packageStatusModuleDistroUnsupported, Class: "warn", Title: "현재 서버용 자동 설치 파일이 없습니다", Detail: "호환 모듈 DEB가 없습니다."},
		"Server":                 ServerRecord{ID: "server-a", Name: "web-a", Inventory: model.Inventory{AgentVersion: "0.2.0", InstallationStage: model.InstallationStagePlanRequired}},
		"InstallationCandidates": []serverInstallationCandidateView{{Kind: "nginx", Version: "1.18.0", BuildHash: "nginx-build", Binary: "/usr/sbin/nginx", PackageManaged: true, UpgradeRecommended: true, RequiredArtifact: "module / nginx / ubuntu / 22.04 / amd64 / build nginx-build"}},
	}
	var output bytes.Buffer
	if err := templates.ExecuteTemplate(&output, "server-detail.html", data); err != nil {
		t.Fatal(err)
	}
	html := output.String()
	for _, expected := range []string{"현재 해야 할 일", "현재 서버용 자동 설치 파일이 없습니다", "Manager에 호환 모듈 추가 필요", "필요 정보 복사", "nginx-build"} {
		if !strings.Contains(html, expected) {
			t.Fatalf("unsupported distro resolution is missing %q: %s", expected, html)
		}
	}
	if strings.Contains(html, `action="/servers/server-a/installation"`) || strings.Contains(html, "패키지 기반으로 설치") {
		t.Fatalf("unsupported distro must not render an install form: %s", html)
	}

	data["InstallationCandidates"] = []serverInstallationCandidateView{{Kind: "nginx", Version: "1.18.0", BuildHash: "nginx-build", Binary: "/usr/sbin/nginx", PackageManaged: true, CustomZIPAvailable: true, UpgradeRecommended: true}}
	output.Reset()
	if err := templates.ExecuteTemplate(&output, "server-detail.html", data); err != nil {
		t.Fatal(err)
	}
	html = output.String()
	if !strings.Contains(html, `name="install_type" value="custom_zip"`) || !strings.Contains(html, "커스텀 ZIP으로 설치") || strings.Contains(html, `name="install_type" value="package"`) {
		t.Fatalf("package-managed server must use exact ZIP fallback when distro module is unavailable: %s", html)
	}
}

func TestServerDetailCanChangeInstalledWebServerControl(t *testing.T) {
	templates, err := webassets.ParseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	session := sessionData{DisplayName: "Operator", Role: RoleEnterpriseAdmin, ActualRole: RoleEnterpriseAdmin, EnterpriseID: "enterprise-a", EnterpriseName: "Example"}.asEnterpriseConsole()
	data := map[string]any{
		"Active": "servers", "Session": session, "CSRF": "token", "ScopeLabel": "Example", "CanOperate": true, "CanManageUsers": true, "AgentSelfUpdateReady": true,
		"Tab":        "packages",
		"AccountURL": "/account", "Server": ServerRecord{ID: "server-a", EnterpriseName: "Example", Name: "web-a", Inventory: model.Inventory{AgentVersion: "1.0.0", WebServer: "nginx", WebServerControl: model.WebServerControlHooks, InstallationStage: model.InstallationStageIntegrationNeeded}},
	}
	var output bytes.Buffer
	if err := templates.ExecuteTemplate(&output, "server-detail.html", data); err != nil {
		t.Fatal(err)
	}
	html := output.String()
	for _, expected := range []string{"정책 재적용 방식 변경", `value="web_control_standard"`, `value="web_control_hooks"`, "재설치 없이"} {
		if !strings.Contains(html, expected) {
			t.Fatalf("installed control UI is missing %q: %s", expected, html)
		}
	}
}

func TestServerDetailOffersAgentOnlyUpdateWithoutInstalledModule(t *testing.T) {
	templates, err := webassets.ParseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	session := sessionData{DisplayName: "Operator", Role: RoleEnterpriseAdmin, ActualRole: RoleEnterpriseAdmin, EnterpriseID: "enterprise-a", EnterpriseName: "Example"}.asEnterpriseConsole()
	data := map[string]any{
		"Active": "servers", "Session": session, "CSRF": "token", "ScopeLabel": "Example", "CanOperate": true, "CanManageUsers": true,
		"Tab": "packages", "AccountURL": "/account", "AgentSelfUpdateReady": true, "AgentPackageAvailable": true, "AgentUpdateAvailable": true, "LatestAgentVersion": "0.2.0",
		"Server": ServerRecord{ID: "server-a", EnterpriseName: "Example", Name: "web-a", Inventory: model.Inventory{AgentVersion: "0.1.0", InstallationStage: model.InstallationStagePlanRequired, Capabilities: []string{model.AgentCapabilitySelfUpdate, model.AgentCapabilityLocalRollback}}},
	}
	var output bytes.Buffer
	if err := templates.ExecuteTemplate(&output, "server-detail.html", data); err != nil {
		t.Fatal(err)
	}
	html := output.String()
	for _, expected := range []string{`action="/servers/server-a/agent-package"`, "Agent 업데이트", "웹서버 모듈, CRS·기업 정책, Apache/Nginx 설정과 reload는 변경하지 않습니다", "0.2.0"} {
		if !strings.Contains(html, expected) {
			t.Fatalf("Agent-only update UI is missing %q: %s", expected, html)
		}
	}
}

func TestServerDetailShowsAgentRollbackOnlyWithConfirmedTarget(t *testing.T) {
	templates, err := webassets.ParseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	data := map[string]any{
		"Active": "servers", "Session": sessionData{DisplayName: "Operator", Role: RoleEnterpriseAdmin, ActualRole: RoleEnterpriseAdmin, EnterpriseID: "enterprise-a", EnterpriseName: "Example"}.asEnterpriseConsole(),
		"CSRF": "token", "ScopeLabel": "Example", "CanOperate": true, "AgentSelfUpdateReady": true, "AgentPackageAvailable": true,
		"Tab": "packages", "AccountURL": "/account", "LatestAgentVersion": "0.3.0",
		"Server": ServerRecord{ID: "server-a", EnterpriseName: "Example", Name: "web-a", Inventory: model.Inventory{AgentVersion: "0.3.0", InstallationStage: model.InstallationStagePlanRequired, Capabilities: []string{model.AgentCapabilitySelfUpdate, model.AgentCapabilityLocalRollback}}},
	}
	var output bytes.Buffer
	if err := templates.ExecuteTemplate(&output, "server-detail.html", data); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), `value="rollback"`) || strings.Contains(output.String(), "Agent가 한 번 재시작") {
		t.Fatalf("rollback action must be hidden without confirmed upgrade history: %s", output.String())
	}
	data["CanRollbackAgent"] = true
	data["RollbackAgentVersion"] = "0.2.0"
	output.Reset()
	if err := templates.ExecuteTemplate(&output, "server-detail.html", data); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `value="rollback"`) || !strings.Contains(output.String(), "Agent 0.2.0으로 롤백") {
		t.Fatalf("confirmed rollback target is missing: %s", output.String())
	}
}

func TestServerRiskActionsRequireExplicitSelection(t *testing.T) {
	templates, err := webassets.ParseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	session := sessionData{DisplayName: "Operator", Role: RoleEnterpriseAdmin, ActualRole: RoleEnterpriseAdmin, EnterpriseID: "enterprise-a", EnterpriseName: "Example"}.asEnterpriseConsole()
	data := map[string]any{
		"Active": "servers", "Session": session, "CSRF": "token", "ScopeLabel": "Example", "CanOperate": true,
		"Tab": "risk", "AccountURL": "/account", "Server": ServerRecord{ID: "server-a", EnterpriseName: "Example", Name: "web-a", Status: "ONLINE"},
	}
	var output bytes.Buffer
	if err := templates.ExecuteTemplate(&output, "server-detail.html", data); err != nil {
		t.Fatal(err)
	}
	html := output.String()
	for _, expected := range []string{"제한된 운영 영역", "Agent 재시작", "Agent 중지", "서버 재시작", "서버 종료", "외부 복구 필요", "서버 등록 해제", `name="server_name_confirm"`, "web-a", "신규 등록 필요"} {
		if !strings.Contains(html, expected) {
			t.Fatalf("server risk UI is missing %q: %s", expected, html)
		}
	}
	if strings.Contains(html, `name="command" required><option`) || strings.Contains(html, ` checked`) {
		t.Fatalf("risk action must not use a default command or preselected confirmation: %s", html)
	}
}

func TestRevokedServerRiskOffersPermanentDeleteOnly(t *testing.T) {
	templates, err := webassets.ParseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	session := sessionData{DisplayName: "Operator", Role: RoleEnterpriseAdmin, ActualRole: RoleEnterpriseAdmin, EnterpriseID: "enterprise-a", EnterpriseName: "Example"}.asEnterpriseConsole()
	data := map[string]any{
		"Active": "servers", "Session": session, "CSRF": "token", "ScopeLabel": "Example", "CanOperate": true, "CanManageUsers": true,
		"Tab": "risk", "AccountURL": "/account", "Server": ServerRecord{ID: "server-a", EnterpriseName: "Example", Name: "web-a", Status: "REVOKED", Revoked: true},
	}
	var output bytes.Buffer
	if err := templates.ExecuteTemplate(&output, "server-detail.html", data); err != nil {
		t.Fatal(err)
	}
	html := output.String()
	for _, expected := range []string{"Agent 인증은 이미 차단되었습니다", "server-delete-card", "서버 영구 삭제", `href="/servers/server-a?tab=risk"`, `action="/servers/server-a/delete"`, `name="server_name_confirm"`, "정책·패키지·보안 이력", "관리자 감사 기록"} {
		if !strings.Contains(html, expected) {
			t.Fatalf("revoked server deletion UI is missing %q: %s", expected, html)
		}
	}
	for _, unexpected := range []string{"Agent 재시작", `action="/servers/server-a/revoke"`} {
		if strings.Contains(html, unexpected) {
			t.Fatalf("revoked server deletion UI contains unavailable action %q: %s", unexpected, html)
		}
	}
}

func TestServerRevokeConfirmationMatchesVisibleName(t *testing.T) {
	if !validServerRevokeConfirmation("web-a", " web-a ") {
		t.Fatal("matching visible server name was rejected")
	}
	if validServerRevokeConfirmation("web-a", "web-b") || validServerRevokeConfirmation("", "") {
		t.Fatal("invalid server revoke confirmation was accepted")
	}
}

func TestServerDetailOnlyOffersLegacyTransitionWithCompatibleAgent(t *testing.T) {
	templates, err := webassets.ParseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	session := sessionData{DisplayName: "Operator", Role: RoleEnterpriseAdmin, ActualRole: RoleEnterpriseAdmin, EnterpriseID: "enterprise-a", EnterpriseName: "Example"}.asEnterpriseConsole()
	data := map[string]any{
		"Active": "servers", "Session": session, "CSRF": "token", "ScopeLabel": "Example", "CanOperate": true, "CanManageUsers": true,
		"Tab": "packages", "AccountURL": "/account", "AgentURL": "https://manager.example:8443", "BootstrapInstallerSHA256": strings.Repeat("a", 64),
		"ModuleVersionLabel": "미설치",
		"Server":             ServerRecord{ID: "server-a", EnterpriseName: "Example", Name: "web-a", Inventory: model.Inventory{AgentVersion: "0.1.0", ModuleVersion: "unknown", InstallationStage: model.InstallationStagePlanRequired}},
	}
	var unavailable bytes.Buffer
	if err := templates.ExecuteTemplate(&unavailable, "server-detail.html", data); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(unavailable.String(), "--upgrade-agent") || strings.Contains(unavailable.String(), "등록 유지 Agent 재설치 명령 복사") {
		t.Fatalf("legacy transition command must be hidden without a compatible Agent: %s", unavailable.String())
	}
	for _, expected := range []string{"먼저 Manager 패키지를 준비해야 합니다", "현재 Agent를 제거해도", "Agent 전환 후 설치 방식을 선택할 수 있습니다", "레거시 Agent 전환이 안 될 때 복구 방법", "mwaf-uninstall --dry-run", "mwaf-uninstall --purge", "신규 등록은 새 서버 ID"} {
		if !strings.Contains(unavailable.String(), expected) {
			t.Fatalf("legacy transition unavailable UI is missing %q: %s", expected, unavailable.String())
		}
	}
	if strings.Contains(unavailable.String(), "모듈 unknown") || !strings.Contains(unavailable.String(), "모듈 미설치") {
		t.Fatalf("unknown module version must be presented as not installed: %s", unavailable.String())
	}
	if strings.Contains(unavailable.String(), `action="/servers/server-a/installation"`) {
		t.Fatalf("module installation form must be hidden before Agent transition: %s", unavailable.String())
	}

	data["AgentPackageAvailable"] = true
	data["LatestAgentVersion"] = "0.2.0"
	var available bytes.Buffer
	if err := templates.ExecuteTemplate(&available, "server-detail.html", data); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"등록 유지 Agent 재설치 명령 복사", "직접 실행 명령 보기", "--upgrade-agent", "새 등록 토큰"} {
		if !strings.Contains(available.String(), expected) {
			t.Fatalf("legacy transition UI is missing %q: %s", expected, available.String())
		}
	}
}

func TestAgentPackageManagementRequiresUpdateAndRollbackCapabilities(t *testing.T) {
	for _, test := range []struct {
		name         string
		capabilities []string
		want         bool
	}{
		{name: "legacy", capabilities: nil, want: false},
		{name: "self update only", capabilities: []string{model.AgentCapabilitySelfUpdate}, want: false},
		{name: "rollback only", capabilities: []string{model.AgentCapabilityLocalRollback}, want: false},
		{name: "managed", capabilities: []string{model.AgentCapabilitySelfUpdate, model.AgentCapabilityLocalRollback}, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := agentPackageManagementReady(model.Inventory{Capabilities: test.capabilities}); got != test.want {
				t.Fatalf("agentPackageManagementReady()=%v want %v", got, test.want)
			}
		})
	}
}
