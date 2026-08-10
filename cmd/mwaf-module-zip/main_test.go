package main

import (
	"archive/zip"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Fhwang0926/m-waf/internal/model"
)

func TestBuildCreatesSelfDescribingCustomModuleZIP(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "input")
	if err := os.MkdirAll(filepath.Join(input, "module"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(input, "integration"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(input, "module", "connector.so"), []byte("connector"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(input, "integration", "mwaf.conf"), []byte("# managed include\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "packages", "custom.zip")
	metadataOutput := filepath.Join(root, "metadata", "custom.json")
	artifact := model.PackageArtifact{
		ID: "custom", Kind: "module", Name: "custom", Version: "1", OSID: "ubuntu", OSVersion: "24.04", Architecture: "amd64",
		WebServer: "nginx", WebServerVersion: "1.24.0", WebServerBuild: "build-a", IntegrationMode: model.IntegrationModeExternal, RuntimeABI: "modsecurity-v3",
		PolicyDelivery: "bundle", Path: "custom.zip", PackageFormat: model.PackageFormatZIP, InstallRoot: "/opt/m-waf",
	}
	if err := build(input, output, metadataOutput, artifact); err != nil {
		t.Fatal(err)
	}
	archive, err := zip.OpenReader(output)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	names := make(map[string]bool)
	for _, entry := range archive.File {
		names[entry.Name] = true
	}
	for _, required := range []string{"mwaf-module.json", "module/connector.so", "integration/mwaf.conf"} {
		if !names[required] {
			t.Fatalf("custom ZIP is missing %s", required)
		}
	}
	raw, err := os.ReadFile(metadataOutput)
	if err != nil {
		t.Fatal(err)
	}
	var actual model.PackageArtifact
	if err := json.Unmarshal(raw, &actual); err != nil {
		t.Fatal(err)
	}
	if actual.PackageFormat != model.PackageFormatZIP || actual.InstallRoot != "/opt/m-waf" || actual.WebServerVersion != "1.24.0" || actual.WebServerBuild != "build-a" {
		t.Fatalf("unexpected custom package metadata: %+v", actual)
	}
}
