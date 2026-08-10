package manager

import (
	"bytes"
	"strings"
	"testing"
	"time"

	webassets "github.com/Fhwang0926/m-waf/web"
)

func TestMonitoringReportTemplate(t *testing.T) {
	templates, err := webassets.ParseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 10, 1, 30, 0, 0, time.UTC)
	session := sessionData{DisplayName: "Viewer", Role: RoleEnterpriseUser, ActualRole: RoleEnterpriseUser, EnterpriseID: "enterprise-a", EnterpriseName: "Example"}.asEnterpriseConsole()
	data := map[string]any{
		"Active": "reports", "Session": session, "CSRF": "token", "ScopeLabel": "Example", "AccountURL": "/account",
		"SelectedPolicyName": "기본 보호 정책", "SelectedServerName": "web-01",
		"Overview": OverviewData{
			GeneratedAt: now, Range: "24h", RangeLabel: "최근 24시간", RangeStart: now.Add(-24 * time.Hour), RangeEnd: now,
			Summary: OverviewSummary{EventCount: 12, BlockedCount: 3, BlockRate: 25, ActiveServers: 1, OnlineServers: 1},
			Series:  []OverviewPoint{{At: now, Events: 4, Blocked: 1}},
		},
	}
	var output bytes.Buffer
	if err := templates.ExecuteTemplate(&output, "reports.html", data); err != nil {
		t.Fatal(err)
	}
	html := output.String()
	for _, expected := range []string{`class="side-link active" href="/reports"`, `action="/reports"`, "보고서 기준", "기본 보호 정책", "web-01", "2026-08-10 10:30:00", "25.0%"} {
		if !strings.Contains(html, expected) {
			t.Fatalf("monitoring report is missing %q: %s", expected, html)
		}
	}
}
