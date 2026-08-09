package manager

import (
	"bytes"
	"net/url"
	"strings"
	"testing"

	"github.com/Fhwang0926/m-waf/internal/crsindex"
	"github.com/Fhwang0926/m-waf/internal/model"
	webassets "github.com/Fhwang0926/m-waf/web"
)

func TestNormalizeOpenSourcePolicyTab(t *testing.T) {
	tests := map[string]string{
		"":          openSourceTabOverview,
		"unknown":   openSourceTabOverview,
		" RULES ":   openSourceTabRules,
		"setup":     openSourceTabSetup,
		"files":     openSourceTabFiles,
		"diff":      openSourceTabDiff,
		"readiness": openSourceTabReadiness,
	}
	for input, expected := range tests {
		if actual := normalizeOpenSourcePolicyTab(input); actual != expected {
			t.Fatalf("normalizeOpenSourcePolicyTab(%q) = %q, want %q", input, actual, expected)
		}
	}
}

func TestNormalizeOpenSourcePolicyFilesView(t *testing.T) {
	for input, expected := range map[string]string{"": openSourceFilesViewFiles, "unknown": openSourceFilesViewFiles, " FILES ": openSourceFilesViewFiles, " DIRECTIVES ": openSourceFilesViewDirectives} {
		if actual := normalizeOpenSourcePolicyFilesView(input); actual != expected {
			t.Fatalf("normalizeOpenSourcePolicyFilesView(%q) = %q, want %q", input, actual, expected)
		}
	}
}

func TestOpenSourceRulePageURLKeepsRulesTab(t *testing.T) {
	detail := openSourcePolicyDetail{
		Policy:  openSourcePolicyView{Source: model.PolicySourceArtifact{ID: "owasp-crs-lts-4.28.0"}},
		FilterQ: "sql injection",
	}
	parsed, err := url.Parse(detail.pageURL(2))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Query().Get("tab") != openSourceTabRules || parsed.Query().Get("page") != "2" || parsed.Query().Get("q") != "sql injection" {
		t.Fatalf("rule page URL did not preserve tab and filters: %s", parsed.String())
	}
}

func TestOpenSourcePolicyTemplateRendersOnlySelectedTab(t *testing.T) {
	templates, err := webassets.ParseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	tabs := []string{openSourceTabOverview, openSourceTabRules, openSourceTabSetup, openSourceTabFiles, openSourceTabDiff, openSourceTabReadiness}
	for _, tab := range tabs {
		t.Run(tab, func(t *testing.T) {
			detail := openSourcePolicyDetail{
				Tab: tab, FilesView: openSourceFilesViewFiles,
				Policy: openSourcePolicyView{
					Source:     model.PolicySourceArtifact{ID: "owasp-crs-lts-4.28.0", Version: "4.28.0", Channel: "lts", Tag: "v4.28.0", Repository: "https://github.com/coreruleset/coreruleset", Commit: "abc123", ArtifactFormat: "policy-bundle-v3"},
					LinkStatus: "AVAILABLE", DBIndexReady: true,
				},
			}
			if tab == openSourceTabSetup {
				detail.Setup = []crsindex.SetupField{{Key: "blocking_paranoia_level", Label: "차단 실행 Paranoia Level", Type: "integer", Default: "1"}}
				detail.SourceSetup = []crsindex.SourceSetupItem{{Key: "blocking_paranoia_level", Value: "1", Managed: true}}
			}
			if tab == openSourceTabRules {
				detail.Rules = []openSourceRuleView{{Rule: crsindex.Rule{ID: 942100, Phase: "2", File: "rules/REQUEST-942.conf"}, KoreanDescription: "SQL 삽입 공격 패턴을 탐지하는 규칙입니다."}}
			}
			if tab == openSourceTabFiles {
				detail.Files = []openSourceFileView{{SourceFile: crsindex.SourceFile{Path: "rules/a.data", Kind: "data", SHA256: strings.Repeat("a", 64)}, RawURL: "/api/file", GitHubURL: "https://example.test/file"}}
				detail.Directives = []openSourceDirectiveView{{SourceDirective: crsindex.SourceDirective{Name: "SecMarker", File: "rules/a.conf", Directive: "SecMarker END"}}}
			}
			data := map[string]any{
				"Active": "open-source-policies", "Session": sessionData{DisplayName: "Operator", Role: RoleSystemAdmin},
				"CSRF": "token", "IsSystemAdmin": true, "CanOperate": true, "CanManageUsers": true,
				"Detail": detail, "HasBase": false, "Diff": openSourcePolicyDiff{},
			}
			var output bytes.Buffer
			if err := templates.ExecuteTemplate(&output, "open-source-policy.html", data); err != nil {
				t.Fatal(err)
			}
			html := output.String()
			if strings.Count(html, `data-crs-tab-panel=`) != 1 || !strings.Contains(html, `data-crs-tab-panel="`+tab+`"`) {
				t.Fatalf("selected tab panel was not isolated: %s", html)
			}
			if !strings.Contains(html, `class="active" href="/open-source-policies/owasp-crs-lts-4.28.0?tab=`+tab+`"`) {
				t.Fatalf("selected tab link is not active: %s", html)
			}
			if strings.Contains(html, `href="#rules"`) || strings.Contains(html, `href="#setup"`) {
				t.Fatalf("legacy in-page anchor tabs remain: %s", html)
			}
			if tab == openSourceTabRules && (!strings.Contains(html, `id="crs-rule-help-942100"`) || !strings.Contains(html, "SQL 삽입 공격 패턴")) {
				t.Fatalf("Korean Rule tooltip is missing: %s", html)
			}
			if tab == openSourceTabSetup {
				if !strings.Contains(html, `class="table-wide crs-inventory-table crs-setup-inventory-table"`) || !strings.Contains(html, "원본 값 전체 보기") {
					t.Fatalf("Setup inventory summary and expandable source value are missing: %s", html)
				}
				if strings.Contains(html, "<th>선언</th>") || strings.Contains(html, "<th>시스템 정책</th>") {
					t.Fatalf("Setup declaration and policy state must be merged into one status column: %s", html)
				}
			}
			pageHeadEnd := strings.Index(html, `<nav class="tabs crs-detail-tabs"`)
			if pageHeadEnd < 0 {
				t.Fatalf("CRS detail tab navigation is missing: %s", html)
			}
			pageHead := html[:pageHeadEnd]
			if !strings.Contains(pageHead, "CRS 목록으로 돌아가기") || strings.Contains(pageHead, "시스템 오버라이드 보기") || strings.Contains(pageHead, "이 CRS로 오버라이드 설정") {
				t.Fatalf("CRS detail header actions are not isolated from override operations: %s", pageHead)
			}
		})
	}
}

func TestOpenSourcePolicyFilesSubviewsRenderSeparately(t *testing.T) {
	templates, err := webassets.ParseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	for _, view := range []string{openSourceFilesViewFiles, openSourceFilesViewDirectives} {
		t.Run(view, func(t *testing.T) {
			detail := openSourcePolicyDetail{
				Tab: openSourceTabFiles, FilesView: view,
				Policy:     openSourcePolicyView{Source: model.PolicySourceArtifact{ID: "owasp-crs-lts-4.25.1", Version: "4.25.1"}},
				Files:      []openSourceFileView{{SourceFile: crsindex.SourceFile{Path: "files-only.data", Kind: "data"}}},
				Directives: []openSourceDirectiveView{{SourceDirective: crsindex.SourceDirective{Name: "DirectivesOnly", File: "rules/a.conf", Directive: "SecMarker END"}}},
			}
			data := map[string]any{
				"Active": "open-source-policies", "Session": sessionData{DisplayName: "Operator", Role: RoleSystemAdmin},
				"CSRF": "token", "IsSystemAdmin": true, "CanOperate": true, "CanManageUsers": true,
				"Detail": detail, "HasBase": false, "Diff": openSourcePolicyDiff{},
			}
			var output bytes.Buffer
			if err := templates.ExecuteTemplate(&output, "open-source-policy.html", data); err != nil {
				t.Fatal(err)
			}
			html := output.String()
			if !strings.Contains(html, `data-crs-inventory-panel="`+view+`"`) || !strings.Contains(html, `view=`+view+`" aria-current="page"`) {
				t.Fatalf("selected inventory subview is not active: %s", html)
			}
			if view == openSourceFilesViewFiles && (strings.Contains(html, "DirectivesOnly") || !strings.Contains(html, "files-only.data")) {
				t.Fatalf("files subview mixed directive content: %s", html)
			}
			if view == openSourceFilesViewDirectives && (strings.Contains(html, "files-only.data") || !strings.Contains(html, "DirectivesOnly") || !strings.Contains(html, "SecMarker END")) {
				t.Fatalf("directives subview mixed file content: %s", html)
			}
			if view == openSourceFilesViewDirectives && (strings.Contains(html, "원본 지시문 보기") || strings.Contains(html, "고정 commit 원본 열기")) {
				t.Fatalf("directives subview must show source without disclosure actions: %s", html)
			}
		})
	}
}

func TestOpenSourcePolicyReadinessHidesActionForCurrentSource(t *testing.T) {
	templates, err := webassets.ParseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	detail := openSourcePolicyDetail{
		Tab: openSourceTabReadiness,
		Policy: openSourcePolicyView{
			Source:               model.PolicySourceArtifact{ID: "owasp-crs-stable-4.28.0", Version: "4.28.0"},
			LinkStatus:           "CURRENT",
			MigrationBlockReason: "현재 기준 정책에 정확히 연동된 CRS입니다.",
		},
	}
	data := map[string]any{
		"Active": "open-source-policies", "Session": sessionData{DisplayName: "Operator", Role: RoleSystemAdmin},
		"CSRF": "token", "IsSystemAdmin": true, "CanOperate": true, "CanManageUsers": true,
		"Detail": detail, "HasBase": false, "Diff": openSourcePolicyDiff{},
	}
	var output bytes.Buffer
	if err := templates.ExecuteTemplate(&output, "open-source-policy.html", data); err != nil {
		t.Fatal(err)
	}
	html := output.String()
	if !strings.Contains(html, "현재 기준 정책에 정확히 연동된 CRS입니다.") {
		t.Fatalf("current-source status guidance is missing: %s", html)
	}
	if strings.Contains(html, "시스템 오버라이드 보기") || strings.Contains(html, "이 CRS로 오버라이드 설정") {
		t.Fatalf("current source must not expose an override action: %s", html)
	}
}

func TestOpenSourceDiffIncludesSourceFilesSetupAndDirectives(t *testing.T) {
	files := compareSourceFiles(
		[]crsindex.SourceFile{{Path: "rules/keywords.data", Kind: "data", SHA256: "old"}},
		[]crsindex.SourceFile{{Path: "rules/keywords.data", Kind: "data", SHA256: "new"}},
	)
	setup := compareSourceSetupItems(
		[]crsindex.SourceSetupItem{{Key: "reporting_level", Value: "3"}},
		[]crsindex.SourceSetupItem{{Key: "reporting_level", Value: "4"}},
	)
	directives := compareSourceDirectives(
		[]crsindex.SourceDirective{{Name: "SecMarker", File: "rules/a.conf", Directive: `SecMarker "END-A"`, ContentHash: "old"}},
		[]crsindex.SourceDirective{{Name: "SecMarker", File: "rules/a.conf", Directive: `SecMarker "END-A"`, ContentHash: "new"}},
	)
	if len(files) != 1 || files[0].Change != "CHANGED" || len(setup) != 1 || setup[0].Change != "CHANGED" || len(directives) != 1 || directives[0].Change != "CHANGED" {
		t.Fatalf("complete CRS source diff was not preserved: files=%#v setup=%#v directives=%#v", files, setup, directives)
	}
}
