package manager

import (
	"bytes"
	"html/template"
	"strings"
	"testing"

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
	templates, err := template.ParseFS(webassets.Assets, "templates/*.html")
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
	for _, label := range []string{"운영 현황", "보안 이벤트", "보호 정책", "IP 정책", "보호 서버", "서버 설치", "사용자 관리", "기업 관리", "CRS 관리", "시스템 정책", "감사 로그", "시스템 설정"} {
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
}

func TestSystemEnterpriseUsersStayInSystemManagement(t *testing.T) {
	templates, err := template.ParseFS(webassets.Assets, "templates/*.html")
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
	templates, err := template.ParseFS(webassets.Assets, "templates/*.html")
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
}
