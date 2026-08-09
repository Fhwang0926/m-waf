package manager

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Fhwang0926/m-waf/internal/crsindex"
	"github.com/Fhwang0926/m-waf/internal/model"
	"github.com/Fhwang0926/m-waf/internal/systempolicy"
	webassets "github.com/Fhwang0926/m-waf/web"
)

func TestSystemPolicyMigrationTemplateUsesGuidedWizard(t *testing.T) {
	templates, err := webassets.ParseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	baseData := map[string]any{
		"Active": "system-policies", "Session": sessionData{DisplayName: "Operator", Role: RoleSystemAdmin},
		"CSRF": "token", "IsSystemAdmin": true, "CanOperate": true, "CanManageUsers": true,
		"Sources":          []model.PolicySourceArtifact{{ID: "crs-4.18.0", Version: "4.18.0", Tag: "v4.18.0", Commit: "abc123"}},
		"SelectedSourceID": "crs-4.18.0", "SelectedSource": model.PolicySourceArtifact{ID: "crs-4.18.0", Version: "4.18.0", Tag: "v4.18.0", Commit: "abc123"}, "HasSource": true,
		"Base": systempolicy.Template{Key: "crs-baseline", Version: "1.0.0"}, "HasBase": true, "BaseID": "crs-baseline@1.0.0",
		"NextVersion": "1.0.0",
		"Setup": []crsindex.SetupField{
			crsindex.SupportedSetup()[4], crsindex.SupportedSetup()[6], crsindex.SupportedSetup()[7], crsindex.SupportedSetup()[15], crsindex.SupportedSetup()[16],
		},
		"SetupValues": map[string]string{
			"early_blocking": "0", "allowed_methods": "GET HEAD POST OPTIONS", "allowed_request_content_type": "|application/json|",
			"max_file_size": "unlimited", "combined_file_sizes": "unlimited",
		},
		"InheritedSetupValues": map[string]string{
			"early_blocking": "0", "allowed_methods": "GET HEAD POST OPTIONS", "allowed_request_content_type": "|application/json|",
			"max_file_size": "unlimited", "combined_file_sizes": "unlimited",
		},
		"SetupOverrides": map[string]bool{}, "BaseSetupValues": map[string]string{},
		"FormName": "OWASP CRS 4.18.0 시스템 보호 정책", "FormMode": "DetectionOnly", "FormRequestBody": true,
	}
	var output bytes.Buffer
	if err := templates.ExecuteTemplate(&output, "system-policy-migration.html", baseData); err != nil {
		t.Fatal(err)
	}
	html := output.String()
	if strings.Count(html, `data-wizard-panel="`) != 5 || !strings.Contains(html, "data-system-policy-wizard") {
		t.Fatalf("system policy wizard structure is incomplete: %s", html)
	}
	if strings.Count(html, "data-step-status") != 5 || strings.Count(html, "data-step-error-count hidden") != 5 {
		t.Fatalf("system policy wizard step states are incomplete: %s", html)
	}
	for _, text := range []string{"기준 선택", "변경 확인", "보호 설정", "예외·Rule", "검증·게시", "고급 CRS 설정", "고급 예외 및 사용자 Rule"} {
		if !strings.Contains(html, text) {
			t.Fatalf("system policy wizard is missing %q", text)
		}
	}
	for _, marker := range []string{`role="tooltip"`, "data-setup-override", "data-setup-token-editor", "unlimited"} {
		if !strings.Contains(html, marker) {
			t.Fatalf("system policy protection guidance is missing %q", marker)
		}
	}
	for _, marker := range []string{"data-system-policy-context-errors", "최신 기준으로 다시 열기", "CRS 소스 선택"} {
		if !strings.Contains(html, marker) {
			t.Fatalf("system policy context recovery is missing %q", marker)
		}
	}
	for _, marker := range []string{`name="confirm_changed_rules"`, "required data-wizard-confirm", `data-confirm-fields="confirm_changed_rules`} {
		if !strings.Contains(html, marker) {
			t.Fatalf("system policy change confirmation gate is missing %q", marker)
		}
	}
	if strings.Contains(html, "검증된 CRS로 마이그레이션") || strings.Contains(html, "migration-steps") {
		t.Fatalf("legacy migration UI is still exposed: %s", html)
	}
}

func TestSystemPolicyVersionWithdrawalEligibility(t *testing.T) {
	tests := []struct {
		name   string
		policy SystemPolicyVersionRecord
		want   bool
	}{
		{name: "unused published", policy: SystemPolicyVersionRecord{Status: systempolicy.StatusPublished}, want: true},
		{name: "unused deprecated", policy: SystemPolicyVersionRecord{Status: systempolicy.StatusDeprecated}, want: true},
		{name: "enterprise using", policy: SystemPolicyVersionRecord{Status: systempolicy.StatusPublished, EnterpriseCount: 1}},
		{name: "rollout active", policy: SystemPolicyVersionRecord{Status: systempolicy.StatusPublished, ActiveRolloutCount: 1}},
		{name: "already withdrawn", policy: SystemPolicyVersionRecord{Status: systempolicy.StatusWithdrawn}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.policy.CanWithdraw(); got != test.want {
				t.Fatalf("CanWithdraw() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestCurrentSystemPolicyTitleLinksToCRSSource(t *testing.T) {
	templates, err := webassets.ParseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	current := systemPolicyVersionView{SystemPolicyVersionRecord: SystemPolicyVersionRecord{
		ID: "crs-baseline@1.0.0", Name: "OWASP CRS 4.25.1 시스템 보호 정책", CRSVersion: "4.25.1", CRSTrack: "lts", Status: systempolicy.StatusPublished,
		Defaults: systempolicy.Defaults{CRSSource: &systempolicy.PolicySourceRef{ID: "owasp-crs-lts-4.25.1"}},
	}}
	data := map[string]any{
		"Active": "system-policies", "Session": sessionData{DisplayName: "Operator", Role: RoleSystemAdmin},
		"CSRF": "token", "IsSystemAdmin": true, "CanOperate": true, "CanManageUsers": true,
		"Tab": "policies", "HasCurrentPolicy": true, "CurrentPolicy": current,
		"Summary": systemPolicyOperationsSummary{}, "Lifecycle": systemPolicyLifecycleView{}, "PublishedResult": systemPolicyPublishedResult{},
	}
	var output bytes.Buffer
	if err := templates.ExecuteTemplate(&output, "system-policies.html", data); err != nil {
		t.Fatal(err)
	}
	html := output.String()
	if !strings.Contains(html, `<a class="system-policy-source-link" href="/open-source-policies/owasp-crs-lts-4.25.1" title="CRS 원본 상세로 이동">`) || !strings.Contains(html, `class="system-policy-source-link-icon"`) {
		t.Fatalf("current system policy title does not link to the CRS source: %s", html)
	}
	if strings.Contains(html, "CRS 원본 확인") {
		t.Fatalf("duplicate CRS source action remains: %s", html)
	}
}

func TestNextSystemPolicyVersionAfterWithdrawal(t *testing.T) {
	if got := nextSystemPolicyVersionAfter(nil); got != "1.0.0" {
		t.Fatalf("empty history next version = %s", got)
	}
	if got := nextSystemPolicyVersionAfter([]string{"1.0.1", "1.0.0", "1.0.2"}); got != "1.0.3" {
		t.Fatalf("withdrawn history next version = %s", got)
	}
}

func TestSystemPolicyMigrationTemplateBlocksWithoutSource(t *testing.T) {
	templates, err := webassets.ParseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	data := map[string]any{
		"Active": "system-policies", "Session": sessionData{DisplayName: "Operator", Role: RoleSystemAdmin},
		"CSRF": "token", "IsSystemAdmin": true, "CanOperate": true, "CanManageUsers": true,
		"Sources": []model.PolicySourceArtifact{}, "Base": systempolicy.Template{Key: "crs-lts-baseline", Version: "1.0.0"}, "HasBase": true,
	}
	var output bytes.Buffer
	if err := templates.ExecuteTemplate(&output, "system-policy-migration.html", data); err != nil {
		t.Fatal(err)
	}
	html := output.String()
	if !strings.Contains(html, "검증된 CRS 소스가 없습니다") || !strings.Contains(html, "CRS 관리로 이동") {
		t.Fatalf("missing source guidance was not rendered: %s", html)
	}
	if strings.Contains(html, "data-system-policy-wizard") {
		t.Fatalf("wizard must not be rendered without a verified CRS source: %s", html)
	}
}

func TestSystemPolicyMigrationTemplateAllowsFirstManagerPolicy(t *testing.T) {
	templates, err := webassets.ParseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	source := model.PolicySourceArtifact{ID: "crs-stable", Version: "4.28.0", Channel: "stable", Tag: "v4.28.0", Commit: "abc123"}
	data := map[string]any{
		"Active": "system-policies", "Session": sessionData{DisplayName: "Operator", Role: RoleSystemAdmin},
		"CSRF": "token", "IsSystemAdmin": true, "CanOperate": true, "CanManageUsers": true,
		"Sources": []model.PolicySourceArtifact{source}, "SelectedSource": source, "SelectedSourceID": source.ID, "HasSource": true,
		"NextVersion": "1.0.0", "SetupValues": map[string]string{}, "BaseSetupValues": map[string]string{},
		"FormName": "CRS 기준 정책", "FormMode": "DetectionOnly", "FormRequestBody": true,
	}
	var output bytes.Buffer
	if err := templates.ExecuteTemplate(&output, "system-policy-migration.html", data); err != nil {
		t.Fatal(err)
	}
	html := output.String()
	if !strings.Contains(html, "최초 시스템 정책 설정") || !strings.Contains(html, `name="source_id" value="crs-stable"`) || !strings.Contains(html, "data-system-policy-wizard") {
		t.Fatalf("first Manager policy wizard is incomplete: %s", html)
	}
}

func TestBuildSystemPolicyLifecycleSelectsNaturalAction(t *testing.T) {
	sources := []model.PolicySourceArtifact{{ID: "crs-new", Version: "4.18.0"}, {ID: "crs-current", Version: "4.17.1"}}
	initial := buildSystemPolicyLifecycle(nil, sources, systempolicy.Template{})
	if initial.CreateLabel != "CRS 관리" || initial.CreateURL != "/open-source-policies" {
		t.Fatalf("initial lifecycle action = %#v", initial)
	}
	current := systempolicy.Template{
		Key: "crs-baseline", Version: "1.2.3", Name: "기준 정책", CRSVersion: "4.17.1",
		Defaults: systempolicy.Defaults{CRSSource: &systempolicy.PolicySourceRef{ID: "crs-current"}},
	}
	items := []SystemPolicyVersionRecord{{ID: current.Reference(), EnterpriseCount: 3, ServerCount: 12}}
	upgrade := buildSystemPolicyLifecycle(items, sources, current)
	if !upgrade.HasNewSource || upgrade.CreateLabel != "시스템 정책 검토" || upgrade.CurrentEnterpriseCount != 3 || upgrade.CurrentServerCount != 12 {
		t.Fatalf("upgrade lifecycle = %#v", upgrade)
	}
	currentOnly := buildSystemPolicyLifecycle(items, sources[1:], current)
	if currentOnly.HasNewSource || currentOnly.CreateLabel != "시스템 정책 수정" || !strings.HasPrefix(currentOnly.CreateURL, "/system-policies/migrations/new?") {
		t.Fatalf("settings-only lifecycle = %#v", currentOnly)
	}
}

func TestClassifyOpenSourcePolicyRequiresExactCurrentPin(t *testing.T) {
	source := model.PolicySourceArtifact{ID: "crs-stable", Version: "4.28.0", Channel: "stable", ArchiveSHA256: "archive", IndexSHA256: "index", ArtifactFormat: "policy-bundle-v3"}
	current := systempolicy.Template{Key: systempolicy.DefaultTemplateKey, Version: "1.0.0", CRSVersion: "4.28.0", CRSTrack: "stable"}
	legacy := classifyOpenSourcePolicyView(openSourcePolicyView{Source: source, DBIndexReady: true}, current)
	if legacy.LinkStatus != "LEGACY_UNPINNED" || !legacy.CanMigrate {
		t.Fatalf("legacy source classification = %#v", legacy)
	}
	current.Defaults.CRSSource = &systempolicy.PolicySourceRef{ID: source.ID, ArchiveSHA256: source.ArchiveSHA256, IndexSHA256: source.IndexSHA256}
	exact := classifyOpenSourcePolicyView(openSourcePolicyView{Source: source, DBIndexReady: true}, current)
	if exact.LinkStatus != "CURRENT" || exact.CanMigrate {
		t.Fatalf("exact source classification = %#v", exact)
	}
	current.Defaults.CRSSource.IndexSHA256 = "different"
	notExact := classifyOpenSourcePolicyView(openSourcePolicyView{Source: source, DBIndexReady: true}, current)
	if notExact.LinkStatus == "CURRENT" {
		t.Fatalf("digest mismatch must not be current: %#v", notExact)
	}
}

func TestSystemPolicyMigrationFormReportsExactAdvancedField(t *testing.T) {
	values := url.Values{"target_exclusions": {"942100"}}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/system-policy-migrations/validate", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_, err := systemPolicyMigrationRequestFromForm(request)
	var fieldError systemPolicyMigrationFieldError
	if !errors.As(err, &fieldError) || fieldError.Field != "target_exclusions" {
		t.Fatalf("field error = %#v, err = %v", fieldError, err)
	}
}

func TestSystemPolicyMigrationFormPreservesExpectedBase(t *testing.T) {
	values := url.Values{
		"expected_system_policy_id": {"crs-baseline@1.0.0"},
		"source_id":                 {"owasp-crs-lts-4.25.1"},
		"name":                      {"CRS 기본 보호 정책"},
		"mode":                      {"DetectionOnly"},
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/system-policy-migrations/validate", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	parsed, err := systemPolicyMigrationRequestFromForm(request)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ExpectedSystemPolicyID != "crs-baseline@1.0.0" || parsed.SourceID != "owasp-crs-lts-4.25.1" {
		t.Fatalf("migration base was not preserved: %#v", parsed)
	}
}

func TestSystemPolicyPublishedURLIncludesResultReference(t *testing.T) {
	candidate := systempolicy.Template{Key: "crs-baseline", Version: "1.2.4", CRSVersion: "4.18.0"}
	location, err := url.Parse(systemPolicyPublishedURL(candidate))
	if err != nil {
		t.Fatal(err)
	}
	if location.Path != "/system-policies" || location.Query().Get("published") != candidate.Reference() || !strings.Contains(location.Query().Get("notice"), "OWASP CRS 4.18.0") || !strings.Contains(location.Query().Get("notice"), "시스템 정책") {
		t.Fatalf("published location = %s", location.String())
	}
}

func TestValidateMigrationSetupAcceptsUnlimitedFileLimits(t *testing.T) {
	fields := crsindex.SupportedSetup()[15:]
	values, fieldErrors := validateMigrationSetup(fields, map[string]string{
		"max_file_size": "unlimited", "combined_file_sizes": "UNLIMITED",
	})
	if len(fieldErrors) != 0 || values["max_file_size"] != "unlimited" || values["combined_file_sizes"] != "unlimited" {
		t.Fatalf("unlimited file limits were not normalized: values=%#v errors=%#v", values, fieldErrors)
	}
}
