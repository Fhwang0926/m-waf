package manager

import (
	"bytes"
	"strings"
	"testing"

	webassets "github.com/Fhwang0926/m-waf/web"
)

func TestMonitoringReportTemplate(t *testing.T) {
	templates, err := webassets.ParseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	session := sessionData{DisplayName: "Viewer", Role: RoleEnterpriseUser, ActualRole: RoleEnterpriseUser, EnterpriseID: "enterprise-a", EnterpriseName: "Example"}.asEnterpriseConsole()
	data := map[string]any{
		"Active": "reports", "Session": session, "CSRF": "token", "ScopeLabel": "Example", "AccountURL": "/account",
	}
	var output bytes.Buffer
	if err := templates.ExecuteTemplate(&output, "reports.html", data); err != nil {
		t.Fatal(err)
	}
	html := output.String()
	for _, expected := range []string{`class="side-link active" href="/reports"`, "준비 중", "보고서 기능을 준비하고 있습니다"} {
		if !strings.Contains(html, expected) {
			t.Fatalf("monitoring report placeholder is missing %q: %s", expected, html)
		}
	}
	for _, unexpected := range []string{"보고서 조회", "인쇄", "시간대별 이벤트"} {
		if strings.Contains(html, unexpected) {
			t.Fatalf("monitoring report placeholder still includes %q: %s", unexpected, html)
		}
	}
}
