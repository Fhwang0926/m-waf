package manager

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	webassets "github.com/Fhwang0926/m-waf/web"
)

func TestIncidentExceptionExpiryEnforcesRiskLimits(t *testing.T) {
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)

	expiresAt, err := incidentExceptionExpiry("url", "", RoleEnterpriseUser, now)
	if err != nil || expiresAt == nil || !expiresAt.Equal(now.Add(30*24*time.Hour)) {
		t.Fatalf("default URL expiry = %v, %v", expiresAt, err)
	}
	if _, err := incidentExceptionExpiry("global", "30d", RoleEnterpriseAdmin, now); err == nil {
		t.Fatal("global exception accepted a 30 day expiry")
	}
	if _, err := incidentExceptionExpiry("url", "permanent", RoleEnterpriseUser, now); err == nil {
		t.Fatal("enterprise user accepted a permanent exception")
	}
	if expiresAt, err := incidentExceptionExpiry("url", "permanent", RoleEnterpriseAdmin, now); err != nil || expiresAt != nil {
		t.Fatalf("enterprise administrator permanent expiry = %v, %v", expiresAt, err)
	}
}

func TestOverlappingPolicyExceptionBlocksDuplicatesAndBroaderRules(t *testing.T) {
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	urlRule := PolicyExclusion{
		SourceScope: PolicyScopeEnterprise, Type: PolicyExclusionRule, LoadStage: PolicyExclusionBefore,
		RuleID: 942100, Enabled: true, Conditions: []PolicyExclusionCondition{{Field: "REQUEST_URI", Operator: "@streq", Value: "/login"}},
	}
	configuration := PolicyConfiguration{Exclusions: []PolicyExclusion{urlRule}}
	if got := overlappingPolicyException(configuration, urlRule, now); got == "" {
		t.Fatal("identical exception was not detected")
	}
	inputTarget := PolicyExclusion{
		SourceScope: PolicyScopeEnterprise, Type: PolicyExclusionTarget, LoadStage: PolicyExclusionBefore,
		RuleID: 942100, Target: "ARGS:username", Enabled: true, Conditions: []PolicyExclusionCondition{{Field: "REQUEST_URI", Operator: "@streq", Value: "/login"}},
	}
	if got := overlappingPolicyException(configuration, inputTarget, now); got == "" {
		t.Fatal("URL-wide exception did not cover a target exception")
	}
}

func TestPolicyExceptionViewsExposeIncidentAndExpiry(t *testing.T) {
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	expiresAt := now.Add(24 * time.Hour)
	configuration := PolicyConfiguration{Exclusions: []PolicyExclusion{{
		ID: "exception-a", SourceScope: PolicyScopeEnterprise, Type: PolicyExclusionTarget, LoadStage: PolicyExclusionBefore,
		RuleID: 942100, Target: "ARGS:username", Enabled: true, Reason: "보안 이벤트 42 · 정상 로그인 요청", ExpiresAt: &expiresAt,
		Conditions: []PolicyExclusionCondition{{Field: "REQUEST_URI", Operator: "@streq", Value: "/login"}},
	}}}
	views := policyExceptionViews(&configuration, now)
	if len(views) != 1 || views[0].IncidentID != "42" || views[0].Reason != "정상 로그인 요청" || views[0].ScopeLabel != "입력 항목" {
		t.Fatalf("unexpected exception view: %#v", views)
	}
}

func TestPreservePolicyExclusionMetadata(t *testing.T) {
	expiresAt := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	current := []PolicyExclusion{{
		Type: PolicyExclusionRule, LoadStage: PolicyExclusionBefore, RuleID: 942100, Enabled: true,
		Reason: "보안 이벤트 42 · 정상 요청", ExpiresAt: &expiresAt,
		Conditions: []PolicyExclusionCondition{{Field: "REQUEST_URI", Operator: "@streq", Value: "/login"}},
	}}
	next := []PolicyExclusion{{
		Type: PolicyExclusionRule, LoadStage: PolicyExclusionBefore, RuleID: 942100, Enabled: true,
		Conditions: []PolicyExclusionCondition{{Field: "REQUEST_URI", Operator: "@streq", Value: "/login"}},
	}}
	preservePolicyExclusionMetadata(next, current)
	if next[0].Reason != current[0].Reason || next[0].ExpiresAt == nil || !next[0].ExpiresAt.Equal(expiresAt) {
		t.Fatalf("metadata was not preserved: %#v", next[0])
	}
}

func TestPolicyUserRuleViewExplainsGuidedRule(t *testing.T) {
	view := policyUserRuleViewFor(EnterprisePolicyRecord{ID: "policy-a", Name: "기본 보호"}, PolicyCustomRule{
		RuleID: 40000, SourceScope: PolicyScopeEnterprise,
		CanonicalSecRule: `SecRule REQUEST_URI "@beginsWith /admin" "id:40000,phase:1,deny,status:403,log,msg:M-WAF guided rule 1"`,
	})
	if !view.Guided || view.TargetLabel != "요청 URL" || view.ConditionLabel != "시작 · /admin" || view.ActionLabel != "차단" {
		t.Fatalf("unexpected user Rule view: %#v", view)
	}
}

func TestLegacyIPRulesRedirectsToUserPolicies(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/ip-rules?enterprise_id=enterprise-a", nil)
	response := httptest.NewRecorder()
	new(Server).legacyIPRulesRedirect(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/user-policies?enterprise_id=enterprise-a&type=ip" {
		t.Fatalf("legacy IP policy redirect = %d %q", response.Code, response.Header().Get("Location"))
	}
}

func TestUserPoliciesTemplateUsesUnifiedManagementName(t *testing.T) {
	templates, err := webassets.ParseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	policy := EnterprisePolicyRecord{ID: "policy-a", Name: "기본 보호", EnterpriseName: "Example", Status: EnterprisePolicyActive, CurrentRevisionID: "revision-a"}
	data := map[string]any{
		"Active": "user-policies", "Session": sessionData{DisplayName: "Operator", Role: RoleEnterpriseUser, ActualRole: RoleEnterpriseUser, EnterpriseID: "enterprise-a", EnterpriseName: "Example"}.asEnterpriseConsole(),
		"CSRF": "token", "ScopeLabel": "Example", "CanOperate": true, "AccountURL": "/account",
		"Policies": []EnterprisePolicyRecord{policy}, "PolicyOptions": []EnterprisePolicyRecord{policy},
		"PolicyExceptions": []policyScopedExceptionView{}, "IPRules": []policyIPRuleView{}, "CustomRules": []policyUserRuleView{},
		"Summary": userPolicySummary{PolicyCount: 1}, "FilterType": "all", "Now": time.Now().UTC(),
	}
	var output bytes.Buffer
	if err := templates.ExecuteTemplate(&output, "user-policies.html", data); err != nil {
		t.Fatal(err)
	}
	html := output.String()
	for _, expected := range []string{"사용자 정책", "/policies/policy-a/ip-rules", "/policies/policy-a/user-rules", "탐지 예외"} {
		if !strings.Contains(html, expected) {
			t.Fatalf("user policy management is missing %q: %s", expected, html)
		}
	}
	if strings.Contains(html, "오버라이드 정책") {
		t.Fatalf("deprecated user-facing name remains: %s", html)
	}
}
