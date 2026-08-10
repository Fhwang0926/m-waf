package agent

import (
	"testing"

	"github.com/Fhwang0926/m-waf/internal/model"
)

func TestAgentOnlyDeploymentIgnoresModuleVersion(t *testing.T) {
	deployment := model.PackageDeployment{Scope: model.PackageScopeAgent, Agent: model.PackageDownload{Version: "0.2.0"}}
	inventory := model.Inventory{AgentVersion: "0.2.0", ModuleVersion: "older-module"}
	if !packageDeploymentMatchesInventory(deployment, inventory) {
		t.Fatal("Agent-only deployment should not require a module version match")
	}
	if got := packageDeploymentAppliedDetail(deployment); got == "" {
		t.Fatal("Agent-only deployment result detail is empty")
	}
}

func TestCombinedDeploymentStillRequiresModuleVersion(t *testing.T) {
	deployment := model.PackageDeployment{
		Agent:  model.PackageDownload{Version: "0.2.0"},
		Module: model.PackageDownload{Version: "4.0.0"},
	}
	inventory := model.Inventory{AgentVersion: "0.2.0", ModuleVersion: "3.0.0"}
	if packageDeploymentMatchesInventory(deployment, inventory) {
		t.Fatal("combined deployment accepted a mismatched module version")
	}
}

func TestSafeAgentUpdateStateID(t *testing.T) {
	for _, valid := range []string{"deployment-123", "abc_DEF"} {
		if !safeStateID(valid) {
			t.Fatalf("safe deployment ID was rejected: %q", valid)
		}
	}
	for _, invalid := range []string{"", "../escape", "with space", "a/b"} {
		if safeStateID(invalid) {
			t.Fatalf("unsafe deployment ID was accepted: %q", invalid)
		}
	}
}
