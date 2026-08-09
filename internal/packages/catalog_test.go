package packages

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Fhwang0926/m-waf/internal/model"
)

func TestLoadAndResolveCompatibleModule(t *testing.T) {
	root := t.TempDir()
	artifacts := []model.PackageArtifact{
		{ID: "agent", Kind: "agent", Name: "mwaf-agent", Version: "1", OSID: "ubuntu", OSVersion: "24.04", Architecture: "amd64", Path: "packages/agent.deb"},
		{ID: "apache", Kind: "module", Name: "mwaf-modsecurity-apache", Version: "1", OSID: "ubuntu", OSVersion: "24.04", Architecture: "amd64", WebServer: "apache", Path: "packages/apache.deb"},
		{ID: "nginx", Kind: "module", Name: "mwaf-modsecurity-nginx", Version: "1", OSID: "ubuntu", OSVersion: "24.04", Architecture: "amd64", WebServer: "nginx", Path: "packages/nginx.deb"},
		{ID: "apache-external", Kind: "module", Name: "mwaf-modsecurity-apache-external", Version: "1", OSID: "ubuntu", OSVersion: "24.04", Architecture: "amd64", WebServer: "apache", IntegrationMode: model.IntegrationModeExternal, Path: "packages/apache-external.deb"},
		{ID: "nginx-external", Kind: "module", Name: "mwaf-modsecurity-nginx-external", Version: "1", OSID: "ubuntu", OSVersion: "24.04", Architecture: "amd64", WebServer: "nginx", IntegrationMode: model.IntegrationModeExternal, Path: "packages/nginx-external.deb"},
	}
	if err := os.MkdirAll(filepath.Join(root, "packages"), 0o755); err != nil {
		t.Fatal(err)
	}
	for i := range artifacts {
		body := []byte(artifacts[i].ID)
		if err := os.WriteFile(filepath.Join(root, artifacts[i].Path), body, 0o644); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(body)
		artifacts[i].Size = int64(len(body))
		artifacts[i].SHA256 = hex.EncodeToString(sum[:])
	}
	manifest := model.BundleManifest{SchemaVersion: 1, BundleVersion: "test", SourceCommit: "commit", CreatedAt: time.Now().UTC(), ManagerAPIMin: "v1", ManagerAPIMax: "v1", Artifacts: artifacts}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, manifestName), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, signatureName), []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, raw))), 0o644); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(root, "bundle.pub")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0o644); err != nil {
		t.Fatal(err)
	}
	catalog, err := Load(root, keyPath, "commit", false)
	if err != nil {
		t.Fatal(err)
	}
	agent, module, err := catalog.Resolve(model.Inventory{OSID: "ubuntu", OSVersion: "24.04", Architecture: "amd64", WebServer: "nginx", WebServerVersion: "1.24.0", WebServerBuild: "nginx-hash"})
	if err != nil {
		t.Fatal(err)
	}
	if agent.ID != "agent" || module.ID != "nginx" {
		t.Fatalf("unexpected resolution: %s %s", agent.ID, module.ID)
	}
	if _, module, err := catalog.Resolve(model.Inventory{OSID: "ubuntu", OSVersion: "24.04", Architecture: "amd64", WebServer: "nginx", WebServerVersion: "1.24.1", WebServerBuild: "different"}); err != nil || module.ID != "nginx" {
		t.Fatalf("expected compatible Ubuntu package, module=%s err=%v", module.ID, err)
	}
	if _, module, err := catalog.Resolve(model.Inventory{OSID: "ubuntu", OSVersion: "24.04", Architecture: "amd64", WebServer: "nginx", WebServerVersion: "1.30.4", WebServerBuild: "custom", IntegrationMode: model.IntegrationModeExternal}); err != nil || module.ID != "nginx-external" {
		t.Fatalf("expected external integration package, module=%s err=%v", module.ID, err)
	}
	manualAgent, err := catalog.ResolveAgent(model.Inventory{OSID: "ubuntu", OSVersion: "24.04", Architecture: "amd64", WebServer: "nginx", InstallationMode: "manual"})
	if err != nil || manualAgent.ID != "agent" {
		t.Fatalf("expected Agent-only resolution for a manual Connector, agent=%s err=%v", manualAgent.ID, err)
	}
}

func TestResolveCRSAcceptsPolicyBundleModuleWithoutEmbeddedCRS(t *testing.T) {
	inventory := model.Inventory{OSID: "ubuntu", OSVersion: "24.04", Architecture: "amd64", WebServer: "nginx"}
	catalog := &Catalog{manifest: model.BundleManifest{Artifacts: []model.PackageArtifact{
		{ID: "agent", Kind: "agent", Version: "2", OSID: "ubuntu", OSVersion: "24.04", Architecture: "amd64"},
		{ID: "filter", Kind: "module", Version: "2", OSID: "ubuntu", OSVersion: "24.04", Architecture: "amd64", WebServer: "nginx", RuntimeABI: "modsecurity-v3", PolicyDelivery: "bundle"},
	}}}
	agent, module, err := catalog.ResolveCRS(inventory, "v4.25.1")
	if err != nil {
		t.Fatal(err)
	}
	if agent.ID != "agent" || module.ID != "filter" {
		t.Fatalf("unexpected policy-only resolution: %s %s", agent.ID, module.ID)
	}
}

func TestValidateHotRuleSetRejectsDuplicateOrOutOfRangeIDs(t *testing.T) {
	rules := "SecRule REQUEST_URI \"@beginsWith /admin\" \"id:10000,phase:1,deny\"\nSecAction \"id:10000,phase:1,pass\"\n"
	digest := sha256.Sum256([]byte(rules))
	item := &model.HotRuleSetArtifact{
		SchemaVersion: 1, Version: "1.0.0", RuleIDMin: 10000, RuleIDMax: 39999,
		SHA256: hex.EncodeToString(digest[:]), Rules: rules,
	}
	if err := ValidateHotRuleSet(item); err == nil {
		t.Fatal("duplicate hot Rule IDs must be rejected")
	}
	item.Rules = "SecAction \"id:40000,phase:1,pass\"\n"
	digest = sha256.Sum256([]byte(item.Rules))
	item.SHA256 = hex.EncodeToString(digest[:])
	if err := ValidateHotRuleSet(item); err == nil {
		t.Fatal("out-of-range hot Rule IDs must be rejected")
	}
}
