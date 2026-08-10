package manager

import (
	"strings"
	"testing"

	"github.com/Fhwang0926/m-waf/internal/model"
)

func TestPackageDeploymentPlanKeepsHookModeOutOfDisplayDetail(t *testing.T) {
	encoded, err := encodePackageDeploymentPlan(model.WebServerControlHooks)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encoded, packageDeploymentPlanPrefix) {
		t.Fatalf("hook plan prefix is missing: %q", encoded)
	}
	plan := decodePackageDeploymentPlan(encoded)
	if plan.WebServerControl != model.WebServerControlHooks {
		t.Fatalf("hook mode was not preserved: %#v", plan)
	}

	encoded, err = encodePackageDeploymentResult(plan, "적용 완료")
	if err != nil {
		t.Fatal(err)
	}
	if got := packageDeploymentDisplayDetail(encoded); got != "적용 완료" {
		t.Fatalf("unexpected display detail %q", got)
	}
	if got := decodePackageDeploymentPlan(encoded).WebServerControl; got != model.WebServerControlHooks {
		t.Fatalf("result update lost hook mode: %q", got)
	}
}

func TestAppliedAgentOnlyDeploymentRequiresSuccessfulManagedAgentUpdate(t *testing.T) {
	agentPlan, err := encodePackageDeploymentPlanWithScope(model.WebServerControlStandard, model.PackageScopeAgent)
	if err != nil {
		t.Fatal(err)
	}
	if !isAppliedAgentOnlyDeployment("APPLIED", agentPlan) {
		t.Fatal("successful Agent-only deployment must be eligible as upgrade evidence")
	}
	if isAppliedAgentOnlyDeployment("PENDING", agentPlan) {
		t.Fatal("pending Agent deployment must not be eligible as upgrade evidence")
	}
	modulePlan, err := encodePackageDeploymentPlan(model.WebServerControlStandard)
	if err != nil {
		t.Fatal(err)
	}
	if isAppliedAgentOnlyDeployment("APPLIED", modulePlan) {
		t.Fatal("combined Agent and module deployment must not be treated as Agent-only upgrade evidence")
	}
}

func TestPackageDeploymentPlanDefaultsToStandardControl(t *testing.T) {
	encoded, err := encodePackageDeploymentPlan("")
	if err != nil {
		t.Fatal(err)
	}
	if encoded != "" {
		t.Fatalf("standard mode should not use an internal envelope: %q", encoded)
	}
	if got := decodePackageDeploymentPlan("").WebServerControl; got != model.WebServerControlStandard {
		t.Fatalf("unexpected default control mode %q", got)
	}
	if _, err := encodePackageDeploymentPlan("shell"); err == nil {
		t.Fatal("arbitrary control mode was accepted")
	}
}

func TestAgentOnlyDeploymentPlanSurvivesResultUpdate(t *testing.T) {
	encoded, err := encodePackageDeploymentPlanWithScope(model.WebServerControlStandard, model.PackageScopeAgent)
	if err != nil {
		t.Fatal(err)
	}
	plan := decodePackageDeploymentPlan(encoded)
	if plan.Scope != model.PackageScopeAgent || plan.WebServerControl != model.WebServerControlStandard {
		t.Fatalf("unexpected Agent-only plan: %#v", plan)
	}
	encoded, err = encodePackageDeploymentResult(plan, "Agent 업데이트 완료")
	if err != nil {
		t.Fatal(err)
	}
	if got := decodePackageDeploymentPlan(encoded).Scope; got != model.PackageScopeAgent {
		t.Fatalf("result update lost Agent-only scope: %q", got)
	}
	if got := packageDeploymentDisplayDetail(encoded); got != "Agent 업데이트 완료" {
		t.Fatalf("unexpected display detail %q", got)
	}
}
