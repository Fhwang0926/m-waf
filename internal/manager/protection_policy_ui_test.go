package manager

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
