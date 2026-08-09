package manager

import (
	"testing"
	"time"

	"github.com/Fhwang0926/m-waf/internal/crsindex"
)

func validStructuredConfiguration() PolicyConfiguration {
	return PolicyConfiguration{
		PolicyRevisionID: "revision", EngineMode: "DetectionOnly",
		BlockingParanoiaLevel: 1, ExecutingParanoiaLevel: 2,
		InboundAnomalyThreshold: 5, OutboundAnomalyThreshold: 4,
		RequestBodyAccess: true, SamplingPercentage: 100, RuleIDNamespaceVersion: 1,
	}
}

func TestPolicyConfigurationValidatesParanoiaAndEmergencyBypass(t *testing.T) {
	configuration := validStructuredConfiguration()
	configuration.ExecutingParanoiaLevel = 0
	if err := configuration.ValidateAt(time.Now().UTC()); err == nil {
		t.Fatal("executing paranoia level below blocking level must be rejected")
	}

	configuration = validStructuredConfiguration()
	configuration.Exclusions = []PolicyExclusion{{
		SourceScope: PolicyScopeEnterprise, Type: PolicyExclusionEngineBypass, LoadStage: PolicyExclusionBefore,
		GeneratedRuleID: 5000, Enabled: true, Reason: "incident", ExpiresAt: timePointer(time.Now().UTC().Add(8 * 24 * time.Hour)),
		Conditions: []PolicyExclusionCondition{{Field: "REQUEST_URI", Operator: "@beginsWith", Value: "/incident"}},
	}}
	if err := configuration.ValidateAt(time.Now().UTC()); err == nil {
		t.Fatal("emergency bypass longer than seven days must be rejected")
	}

	configuration.Exclusions[0].Legacy = true
	configuration.Exclusions[0].ExpiresAt = nil
	if err := configuration.ValidateAt(time.Now().UTC()); err != nil {
		t.Fatalf("legacy bypass semantics must remain readable: %v", err)
	}
}

func TestConfigurationRuleIDsAndReferencesUseSelectedCRSIndex(t *testing.T) {
	configuration := validStructuredConfiguration()
	configuration.Setup = []CRSSetupValue{{Key: "allowed_methods", Value: "GET POST", SourceScope: PolicyScopeSystem}}
	configuration.Exclusions = []PolicyExclusion{{SourceScope: PolicyScopeEnterprise, Type: PolicyExclusionRule, LoadStage: PolicyExclusionAfter, RuleID: 942100, Enabled: true}}
	configuration.CustomRules = []PolicyCustomRule{{SourceScope: PolicyScopeEnterprise, RuleID: 40000, Phase: "2", CanonicalSecRule: `SecRule REQUEST_URI "@streq /health" "id:40000,phase:2,pass,nolog"`, Enabled: true}}
	configuration.Normalize()
	index := crsindex.Index{
		Setup: []crsindex.SetupField{{Key: "allowed_methods", Type: "list", Default: "GET", Description: "methods"}},
		Rules: []crsindex.Rule{{ID: 942100, ContentHash: repeatPolicyHex("a"), Tags: []string{"attack-sqli"}}},
	}
	if err := configuration.ValidateAt(time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := validateConfigurationRuleIDs(configuration, index); err != nil {
		t.Fatal(err)
	}
	configuration.CustomRules[0].RuleID = 942100
	configuration.CustomRules[0].CanonicalSecRule = `SecRule REQUEST_URI "@streq /health" "id:942100,phase:2,pass,nolog"`
	configuration.Normalize()
	if err := validateConfigurationRuleIDs(configuration, index); err == nil {
		t.Fatal("custom Rule ID collision with CRS must be rejected")
	}
}

func TestPolicyConfigurationEnforcesExclusionLoadStages(t *testing.T) {
	configuration := validStructuredConfiguration()
	configuration.Exclusions = []PolicyExclusion{{
		SourceScope: PolicyScopeEnterprise, Type: PolicyExclusionRule, LoadStage: PolicyExclusionBefore,
		RuleID: 942100, Enabled: true,
	}}
	if err := configuration.ValidateAt(time.Now().UTC()); err == nil {
		t.Fatal("a BEFORE_CRS exclusion without runtime conditions must be rejected")
	}

	configuration.Exclusions = []PolicyExclusion{{
		SourceScope: PolicyScopeEnterprise, Type: PolicyExclusionRule, LoadStage: PolicyExclusionAfter,
		RuleID: 942100, GeneratedRuleID: 5000, Enabled: true,
	}}
	if err := configuration.ValidateAt(time.Now().UTC()); err == nil {
		t.Fatal("an AFTER_CRS exclusion must not reserve a runtime Rule ID")
	}
}

func TestNewConfigurationRejectsLegacyCustomRuleID(t *testing.T) {
	configuration := validStructuredConfiguration()
	configuration.CustomRules = []PolicyCustomRule{{
		SourceScope: PolicyScopeEnterprise, RuleID: 100001, Phase: "2",
		CanonicalSecRule: `SecRule REQUEST_URI "@streq /legacy" "id:100001,phase:2,pass,nolog"`,
		Enabled:          true, LegacyIDRange: true,
	}}
	configuration.Normalize()
	if err := configuration.ValidateAt(time.Now().UTC()); err != nil {
		t.Fatalf("legacy snapshot must remain readable before authoring validation: %v", err)
	}
	if err := validateConfigurationRuleIDs(configuration, crsindex.Index{}); err == nil {
		t.Fatal("legacy custom Rule IDs must be rejected for a new revision")
	}
}

func TestPolicyIPRulesCanonicalizeAndLimitTrustExpiry(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	canonical, err := canonicalPolicyNetwork("192.0.2.91")
	if err != nil || canonical != "192.0.2.91/32" {
		t.Fatalf("single IPv4 must become a canonical host CIDR: %q %v", canonical, err)
	}
	canonical, err = canonicalPolicyNetwork("2001:db8::9")
	if err != nil || canonical != "2001:db8::9/128" {
		t.Fatalf("single IPv6 must become a canonical host CIDR: %q %v", canonical, err)
	}

	configuration := validStructuredConfiguration()
	configuration.IPRules = []PolicyIPRule{{
		SourceScope: PolicyScopeEnterprise, Action: PolicyIPActionTrust, Network: "192.0.2.91/32",
		GeneratedRuleID: 5000, Reason: "temporary vendor access", ExpiresAt: timePointer(now.Add(24 * time.Hour)), Enabled: true,
	}}
	if err := configuration.ValidateAt(now); err != nil {
		t.Fatalf("24 hour trust rule must be accepted: %v", err)
	}
	configuration.IPRules[0].ExpiresAt = timePointer(now.Add(7*24*time.Hour + time.Second))
	if err := configuration.ValidateAt(now); err == nil {
		t.Fatal("trust rules longer than seven days must be rejected")
	}
}

func TestGuidedRulesRejectAdvancedFieldsAndOperators(t *testing.T) {
	if _, err := mergeGuidedPolicyRules("", []guidedPolicyRule{{Field: "REMOTE_ADDR", Operator: "@streq", Value: "192.0.2.1", Action: "block"}}); err == nil {
		t.Fatal("simple rules must not accept IP fields")
	}
	if _, err := mergeGuidedPolicyRules("", []guidedPolicyRule{{Field: "REQUEST_URI", Operator: "@rx", Value: "^/admin", Action: "block"}}); err == nil {
		t.Fatal("simple rules must not accept regular expressions")
	}
	if _, err := mergeGuidedPolicyRules("", []guidedPolicyRule{{Field: "REQUEST_HEADERS:User-Agent", Operator: "@contains", Value: "scanner", Action: "detect"}}); err != nil {
		t.Fatalf("supported simple rule must be accepted: %v", err)
	}
	rendered, err := mergeGuidedPolicyRules(`SecRule REQUEST_URI "@streq /legacy" "id:41000,phase:2,pass,nolog"`, []guidedPolicyRule{{Field: "ARGS", Argument: "search", Operator: "@contains", Value: "select", Action: "block"}})
	if err != nil {
		t.Fatal(err)
	}
	advanced, guided := splitGuidedPolicyRules(rendered)
	if advanced == "" || len(guided) != 1 || guided[0].Field != "ARGS" || guided[0].Argument != "search" || guided[0].Action != "block" {
		t.Fatalf("simple rules must remain editable without changing advanced rules: %q %#v", advanced, guided)
	}
}

func timePointer(value time.Time) *time.Time { return &value }

func repeatPolicyHex(value string) string {
	result := ""
	for len(result) < 64 {
		result += value
	}
	return result
}
