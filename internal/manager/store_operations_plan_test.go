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
