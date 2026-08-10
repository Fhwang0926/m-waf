package manager

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Fhwang0926/m-waf/internal/systempolicy"
	webassets "github.com/Fhwang0926/m-waf/web"
)

func TestProtectionPolicyFormUsesServerMembershipAndPublishedSystemPolicy(t *testing.T) {
	templates, err := webassets.ParseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	session := sessionData{DisplayName: "Operator", Role: RoleEnterpriseAdmin, ActualRole: RoleEnterpriseAdmin, EnterpriseID: "enterprise-a", EnterpriseName: "Example"}.asEnterpriseConsole()
	data := map[string]any{
		"Active": "policies", "Session": session, "CSRF": "token", "ScopeLabel": "Example", "CanOperate": true,
		"AccountURL": "/account", "FormEnterpriseID": "enterprise-a", "HasSystemPolicy": true,
		"DefaultTemplate": systempolicy.Template{Key: systempolicy.DefaultTemplateKey, Version: "1.2.0", CRSVersion: "4.28.0", Status: systempolicy.StatusPublished},
		"Servers": []policyServerChoice{
			{Server: ServerRecord{ID: "server-a", Name: "web-a"}},
			{Server: ServerRecord{ID: "server-b", Name: "web-b", EnterprisePolicyName: "기존 정책"}},
		},
		"FormStrategy": "MANUAL", "FormMode": "DetectionOnly", "FormParanoia": "1", "FormExecutingParanoia": "1",
		"FormScore": "5", "FormOutboundScore": "4", "FormSamplingPercentage": "100",
	}
	var output bytes.Buffer
	if err := templates.ExecuteTemplate(&output, "policy.html", data); err != nil {
		t.Fatal(err)
	}
	html := output.String()
	if strings.Count(html, `name="server_ids"`) != 2 || !strings.Contains(html, "현재 정책: 기존 정책") {
		t.Fatalf("protection policy form does not expose multi-server membership: %s", html)
	}
	if !strings.Contains(html, "현재 게시된 시스템 정책을 자동으로 사용합니다") || !strings.Contains(html, "OWASP CRS LTS 4.28.0") {
		t.Fatalf("published system policy inheritance is not read-only and visible: %s", html)
	}
	if !strings.Contains(html, `name="scalar_source"`) || !strings.Contains(html, "기본 정책 그대로 사용") || !strings.Contains(html, "기업 설정으로 오버라이드") {
		t.Fatalf("base policy and enterprise override choice is missing: %s", html)
	}
	if strings.Contains(html, `name="target"`) || strings.Contains(html, `name="group_id"`) {
		t.Fatalf("legacy target controls remain in protection policy form: %s", html)
	}
}

func TestLegacyGroupReadRedirectsToProtectionPolicies(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/groups/legacy?enterprise_id=enterprise-a", nil)
	response := httptest.NewRecorder()
	new(Server).legacyGroupsRedirect(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/policies?enterprise_id=enterprise-a" {
		t.Fatalf("legacy group link did not redirect to protection policies: status=%d location=%q", response.Code, response.Header().Get("Location"))
	}
}

func TestPolicyValidationRequestAcceptsServerIDsInsteadOfTarget(t *testing.T) {
	var request policyValidationRequest
	if err := json.Unmarshal([]byte(`{"enterprise_id":"enterprise-a","server_ids":["server-a","server-b"],"target":"group:legacy"}`), &request); err != nil {
		t.Fatal(err)
	}
	if request.EnterpriseID != "enterprise-a" || len(request.ServerIDs) != 2 {
		t.Fatalf("server membership validation request was not decoded: %+v", request)
	}
	normalized, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(normalized), `"target"`) {
		t.Fatalf("legacy target remains in the validation contract: %s", normalized)
	}
}

func TestEnterprisePolicyDetailTabSelection(t *testing.T) {
	for input, expected := range map[string]string{
		"":          "overview",
		"overview":  "overview",
		" SERVERS ": "servers",
		"rules":     "rules",
		"rollouts":  "rollouts",
		"revisions": "revisions",
		"unknown":   "overview",
	} {
		if actual := enterprisePolicyDetailTab(input); actual != expected {
			t.Fatalf("enterprisePolicyDetailTab(%q) = %q, want %q", input, actual, expected)
		}
	}
}

func TestEnterprisePolicyDetailRendersOnlySelectedTab(t *testing.T) {
	templates, err := webassets.ParseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	data := map[string]any{
		"Active": "policies", "Session": sessionData{DisplayName: "Operator", Role: RoleEnterpriseUser, ActualRole: RoleEnterpriseUser, EnterpriseID: "enterprise-a", EnterpriseName: "Example"}.asEnterpriseConsole(),
		"CSRF": "token", "ScopeLabel": "Example", "CanOperate": true, "AccountURL": "/account",
		"Policy": EnterprisePolicyRecord{
			ID: "policy-a", EnterpriseID: "enterprise-a", EnterpriseName: "Example", Name: "CRS 기본 보호 정책", Status: EnterprisePolicyActive,
			CurrentSystemPolicyVersion: "1.0.0", CurrentCRSVersion: "4.28.0", UpdateStrategy: PolicyStrategyManual, CurrentMode: "DetectionOnly", CurrentRevisionID: "revision-a",
		},
		"PolicyServers": []ServerRecord{}, "PolicyServerChoices": []policyServerChoice{}, "Rollouts": []policyRolloutView{}, "Revisions": []PolicyRevisionRecord{},
	}
	tabs := []string{"overview", "servers", "rules", "rollouts", "revisions"}
	for _, selected := range tabs {
		data["Tab"] = selected
		var output bytes.Buffer
		if err := templates.ExecuteTemplate(&output, "enterprise-policy.html", data); err != nil {
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
		if !strings.Contains(html, `aria-current="page"`) || strings.Contains(html, `href="#`) {
			t.Fatalf("%s tab navigation is not URL based and active: %s", selected, html)
		}
		if (selected == "overview") != strings.Contains(html, "운영 제어") {
			t.Fatalf("overview operations visibility is incorrect for %s: %s", selected, html)
		}
	}
}

func TestEnterprisePolicyRedirectKeepsSelectedTab(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/policies/policy-a/servers", nil)
	request.Form = url.Values{"return_tab": {"servers"}}
	response := httptest.NewRecorder()
	new(Server).redirectEnterprisePolicy(response, request, "policy-a", "완료")
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusSeeOther || location.Path != "/policies/policy-a" || location.Query().Get("tab") != "servers" || location.Query().Get("notice") != "완료" {
		t.Fatalf("selected tab redirect was not preserved: status=%d location=%q", response.Code, response.Header().Get("Location"))
	}
}

func TestRolloutTargetFailureIncludesReportedDeploymentFailures(t *testing.T) {
	for name, target := range map[string]PolicyRolloutTargetRecord{
		"target":     {Status: "FAILED"},
		"transition": {Status: "TRANSITION_PENDING", TransitionPolicyStatus: "FAILED"},
		"package":    {Status: "PACKAGE_PENDING", PackageStatus: "FAILED"},
		"policy":     {Status: "POLICY_PENDING", PolicyStatus: "FAILED"},
	} {
		if !rolloutTargetFailed(target) {
			t.Fatalf("%s failure was not detected: %+v", name, target)
		}
	}
	if rolloutTargetFailed(PolicyRolloutTargetRecord{Status: "APPLIED", PolicyStatus: "FAILED"}) {
		t.Fatal("an applied rollout target must not be recovered again")
	}
}
