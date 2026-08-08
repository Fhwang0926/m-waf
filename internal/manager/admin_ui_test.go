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
	render := func(role Role) string {
		t.Helper()
		session := sessionData{DisplayName: "Operator", Role: role, EnterpriseName: "Example"}
		data := map[string]any{
			"Active": "dashboard", "Session": session, "CSRF": "token",
			"IsSystemAdmin": session.IsSystemAdmin(), "CanOperate": session.CanOperate(), "CanManageUsers": session.CanManageUsers(),
		}
		var output bytes.Buffer
		if err := templates.ExecuteTemplate(&output, "navigation", data); err != nil {
			t.Fatal(err)
		}
		return output.String()
	}

	system := render(RoleSystemAdmin)
	if !strings.Contains(system, "시스템 관리") || !strings.Contains(system, "사용자 관리") || !strings.Contains(system, "CRS 소스") || !strings.Contains(system, "정책 버전") {
		t.Fatalf("system administrator navigation is incomplete: %s", system)
	}
	admin := render(RoleEnterpriseAdmin)
	if strings.Contains(admin, "시스템 관리") || !strings.Contains(admin, "사용자 관리") {
		t.Fatalf("enterprise administrator navigation is incorrect: %s", admin)
	}
	user := render(RoleEnterpriseUser)
	if strings.Contains(user, "시스템 관리") || strings.Contains(user, "사용자 관리") {
		t.Fatalf("enterprise user navigation exposes restricted menus: %s", user)
	}
	if !strings.Contains(user, `class="side-link active" href="/"`) {
		t.Fatalf("dashboard navigation is not active: %s", user)
	}
}
