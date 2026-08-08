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

func timePointer(value time.Time) *time.Time { return &value }

func repeatPolicyHex(value string) string {
	result := ""
	for len(result) < 64 {
		result += value
	}
	return result
}
