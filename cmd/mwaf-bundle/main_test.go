package main

import (
	"testing"

	"github.com/Fhwang0926/m-waf/internal/model"
)

func TestSameTargetSeparatesExternalAndDistroIntegrations(t *testing.T) {
	legacyDistro := model.PackageArtifact{Kind: "module", OSID: "ubuntu", OSVersion: "24.04", Architecture: "amd64", WebServer: "nginx"}
	explicitDistro := legacyDistro
	explicitDistro.IntegrationMode = model.IntegrationModeDistro
	external := legacyDistro
	external.IntegrationMode = model.IntegrationModeExternal

	if !sameTarget(explicitDistro, legacyDistro) {
		t.Fatal("legacy module target should remain compatible with explicit distro mode")
	}
	if sameTarget(external, legacyDistro) {
		t.Fatal("external integration must not use a distro module as its rollback target")
	}
}
