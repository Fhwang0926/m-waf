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
	for _, label := range []string{"운영 현황", "보안 이벤트", "보고서", "보호 정책", "IP 정책", "보호 서버", "서버 설치", "사용자 관리", "기업 관리", "CRS 관리", "시스템 정책", "감사 로그", "시스템 설정"} {
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
	if strings.Contains(admin, "CRS 관리") || strings.Contains(admin, "시스템 정책") || strings.Contains(admin, "시스템 설정") || !strings.Contains(admin, "사용자 관리") || !strings.Contains(admin, "IP 정책") || !strings.Contains(admin, "서버 설치") {
		t.Fatalf("enterprise administrator navigation is incorrect: %s", admin)
	}
	user := render(RoleEnterpriseUser)
	if strings.Contains(user, "CRS 관리") || strings.Contains(user, "시스템 정책") || strings.Contains(user, "시스템 설정") || strings.Contains(user, "사용자 관리") || !strings.Contains(user, "보호 정책") || !strings.Contains(user, "IP 정책") || !strings.Contains(user, "서버 설치") {
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
	for _, expected := range []string{"Agent 설치와 자동 등록", "Agent 설치 명령 복사", "별도 입력이 필요하지 않습니다", `data-enrollment-command`, `data-enterprise-id="enterprise-1"`, `data-csrf="token"`, `class="install-command-details"`, "__MWAF_ENROLLMENT_TOKEN__", "Debian 12", "Ubuntu 18.04", "Agent 등록 전용", "Docker", "환경 자동 감지", "wget --no-check-certificate", "sha256sum -c -", "--bootstrap-pin", "--token-stdin", strings.Repeat("a", 64)} {
		if !strings.Contains(html, expected) {
			t.Fatalf("quick install content %q is missing: %s", expected, html)
		}
	}
	if strings.Contains(html, "install-quick-steps") {
		t.Fatalf("redundant install step cards remain: %s", html)
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
		`ubuntu:18.04|ubuntu:24.04|debian:12`,
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
	for _, expected := range []string{"시스템 정보", "/static/brand-ubuntu.png", "Ubuntu 18.04", "amd64", "8 코어", "8.0 GiB", "온라인", "적용 완료", "기본 보호 정책"} {
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
		"Active": "servers", "Session": session, "CSRF": "token", "ScopeLabel": "Example", "CanOperate": true, "CanManageUsers": true,
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
	for _, expected := range []string{"Agent가 먼저 서버를 점검합니다", "패키지 기반 설치", "커스텀 ZIP 설치", "/opt/m-waf", `action="/servers/server-a/installation"`, `name="web_server_control"`, "표준 웹서버 제어", "고객 Hook 사용", "/opt/m-waf/hooks/nginx/configtest", "/opt/m-waf/hooks/nginx/reload"} {
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
}

func TestServerDetailCanChangeInstalledWebServerControl(t *testing.T) {
	templates, err := webassets.ParseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	session := sessionData{DisplayName: "Operator", Role: RoleEnterpriseAdmin, ActualRole: RoleEnterpriseAdmin, EnterpriseID: "enterprise-a", EnterpriseName: "Example"}.asEnterpriseConsole()
	data := map[string]any{
		"Active": "servers", "Session": session, "CSRF": "token", "ScopeLabel": "Example", "CanOperate": true, "CanManageUsers": true,
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
	for _, expected := range []string{`action="/servers/server-a/agent-package"`, "Agent 업데이트", "웹서버 모듈, 정책, Apache/Nginx 설정은 변경하지 않습니다", "Manager 최신 0.2.0"} {
		if !strings.Contains(html, expected) {
			t.Fatalf("Agent-only update UI is missing %q: %s", expected, html)
		}
	}
}
