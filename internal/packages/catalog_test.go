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
		{ID: "filter", Kind: "module", Version: "7", OSID: "ubuntu", OSVersion: "24.04", Architecture: "amd64", WebServer: "nginx", RuntimeABI: "modsecurity-v3", PolicyDelivery: "bundle"},
	}}}
	agent, module, err := catalog.ResolveCRS(inventory, "v4.25.1")
	if err != nil {
		t.Fatal(err)
	}
	if agent.ID != "agent" || module.ID != "filter" {
		t.Fatalf("unexpected policy-only resolution: %s %s", agent.ID, module.ID)
	}
}

func TestResolveSupportedDEBTargetMatrix(t *testing.T) {
	targets := []struct {
		osID       string
		osVersion  string
		webServers []string
	}{
		{osID: "ubuntu", osVersion: "18.04", webServers: []string{"apache"}},
		{osID: "ubuntu", osVersion: "20.04", webServers: []string{"apache"}},
		{osID: "ubuntu", osVersion: "22.04", webServers: []string{"apache"}},
		{osID: "ubuntu", osVersion: "24.04", webServers: []string{"apache", "nginx"}},
		{osID: "ubuntu", osVersion: "26.04", webServers: []string{"apache", "nginx"}},
		{osID: "debian", osVersion: "12", webServers: []string{"apache", "nginx"}},
	}
	var artifacts []model.PackageArtifact
	for _, target := range targets {
		prefix := target.osID + "-" + target.osVersion
		artifacts = append(artifacts, model.PackageArtifact{ID: prefix + "-agent", Kind: "agent", Version: "1", OSID: target.osID, OSVersion: target.osVersion, Architecture: "amd64"})
		for _, webServer := range target.webServers {
			artifacts = append(artifacts, model.PackageArtifact{ID: prefix + "-" + webServer, Kind: "module", Version: "1", OSID: target.osID, OSVersion: target.osVersion, Architecture: "amd64", WebServer: webServer})
		}
	}
	catalog := &Catalog{manifest: model.BundleManifest{Artifacts: artifacts}}
	for _, target := range targets {
		for _, webServer := range target.webServers {
			inventory := model.Inventory{OSID: target.osID, OSVersion: target.osVersion, Architecture: "amd64", WebServer: webServer}
			agent, module, err := catalog.Resolve(inventory)
			if err != nil {
				t.Fatalf("resolve %s %s %s: %v", target.osID, target.osVersion, webServer, err)
			}
			if agent.OSID != target.osID || agent.OSVersion != target.osVersion || module.WebServer != webServer {
				t.Fatalf("unexpected resolution for %s %s %s: agent=%+v module=%+v", target.osID, target.osVersion, webServer, agent, module)
			}
		}
	}
	for _, osVersion := range []string{"18.04", "20.04", "22.04"} {
		if _, _, err := catalog.Resolve(model.Inventory{OSID: "ubuntu", OSVersion: osVersion, Architecture: "amd64", WebServer: "nginx"}); err == nil {
			t.Fatalf("Ubuntu %s must not advertise a distro Nginx module", osVersion)
		}
	}
}

func TestResolveLegacyUbuntuAgentsWithApacheOnly(t *testing.T) {
	artifacts := []model.PackageArtifact{
		{ID: "ubuntu-24.04-module", Kind: "module", Version: "1", OSID: "ubuntu", OSVersion: "24.04", Architecture: "amd64", WebServer: "nginx"},
	}
	for _, osVersion := range []string{"18.04", "20.04", "22.04"} {
		artifacts = append(artifacts,
			model.PackageArtifact{ID: "ubuntu-" + osVersion + "-agent", Kind: "agent", Version: "1", OSID: "ubuntu", OSVersion: osVersion, Architecture: "amd64"},
			model.PackageArtifact{ID: "ubuntu-" + osVersion + "-apache", Kind: "module", Version: "1", OSID: "ubuntu", OSVersion: osVersion, Architecture: "amd64", WebServer: "apache"},
		)
	}
	catalog := &Catalog{manifest: model.BundleManifest{Artifacts: artifacts}}
	for _, osVersion := range []string{"18.04", "20.04", "22.04"} {
		apacheInventory := model.Inventory{OSID: "ubuntu", OSVersion: osVersion, Architecture: "amd64", WebServer: "apache"}
		agent, module, err := catalog.Resolve(apacheInventory)
		if err != nil || agent.ID != "ubuntu-"+osVersion+"-agent" {
			t.Fatalf("expected Ubuntu %s Apache resolution, agent=%+v module=%+v err=%v", osVersion, agent, module, err)
		}
		nginxInventory := model.Inventory{OSID: "ubuntu", OSVersion: osVersion, Architecture: "amd64", WebServer: "nginx"}
		if _, _, err := catalog.Resolve(nginxInventory); err == nil {
			t.Fatalf("Ubuntu %s must not advertise a distro Nginx module", osVersion)
		}
	}
}

func TestRollbackAgentDoesNotRequireModule(t *testing.T) {
	catalog := &Catalog{byID: map[string]model.PackageArtifact{
		"agent-new": {ID: "agent-new", Kind: "agent", RollbackID: "agent-old"},
		"agent-old": {ID: "agent-old", Kind: "agent"},
	}}
	rollback, err := catalog.RollbackAgent("agent-new")
	if err != nil {
		t.Fatal(err)
	}
	if rollback.ID != "agent-old" {
		t.Fatalf("unexpected Agent rollback target %q", rollback.ID)
	}
	if _, err := catalog.RollbackAgent("agent-old"); err == nil {
		t.Fatal("Agent without rollback metadata must not roll back")
	}
}

func TestResolveCustomZIPRequiresExactBuild(t *testing.T) {
	inventory := model.Inventory{OSID: "ubuntu", OSVersion: "24.04", Architecture: "amd64", WebServer: "nginx", WebServerVersion: "1.24.0", WebServerBuild: "build-a", IntegrationMode: model.IntegrationModeExternal, InstallationMode: model.InstallationModeCustomZIP}
	catalog := &Catalog{manifest: model.BundleManifest{Artifacts: []model.PackageArtifact{
		{ID: "agent", Kind: "agent", Version: "1", OSID: "ubuntu", OSVersion: "24.04", Architecture: "amd64"},
		{ID: "external-deb", Kind: "module", Version: "1", OSID: "ubuntu", OSVersion: "24.04", Architecture: "amd64", WebServer: "nginx", IntegrationMode: model.IntegrationModeExternal},
		{ID: "custom-a", Kind: "module", Version: "1", OSID: "ubuntu", OSVersion: "24.04", Architecture: "amd64", WebServer: "nginx", WebServerVersion: "1.24.0", WebServerBuild: "build-a", IntegrationMode: model.IntegrationModeExternal, RuntimeABI: "modsecurity-v3", PackageFormat: model.PackageFormatZIP, InstallRoot: "/opt/m-waf"},
	}}}
	agent, module, err := catalog.Resolve(inventory)
	if err != nil {
		t.Fatal(err)
	}
	if agent.ID != "agent" || module.ID != "custom-a" {
		t.Fatalf("unexpected custom ZIP resolution: %s %s", agent.ID, module.ID)
	}
	inventory.WebServerBuild = "build-b"
	if _, _, err := catalog.Resolve(inventory); err == nil {
		t.Fatal("a custom ZIP for a different web-server build must not resolve")
	}
	inventory.WebServerBuild = "build-a"
	inventory.WebServerVersion = "1.25.0"
	if _, err := catalog.ResolveModule(inventory); err == nil {
		t.Fatal("a custom ZIP for a different web-server version must not resolve")
	}
	inventory.WebServerVersion = "1.24.0"
	inventory.WebServerBuild = "build-a"
	catalog.manifest.Artifacts[2].InstallRoot = "/usr/local/mwaf"
	if _, err := catalog.ResolveModule(inventory); err == nil {
		t.Fatal("a custom ZIP outside /opt/m-waf must not resolve")
	}
}

func TestResolveModuleDoesNotRequireAgentArtifact(t *testing.T) {
	inventory := model.Inventory{OSID: "ubuntu", OSVersion: "18.04", Architecture: "amd64", WebServer: "apache", WebServerVersion: "2.4.29", WebServerBuild: "apache-build", IntegrationMode: model.IntegrationModeExternal, InstallationMode: model.InstallationModeCustomZIP}
	catalog := &Catalog{manifest: model.BundleManifest{Artifacts: []model.PackageArtifact{
		{ID: "custom-apache", Kind: "module", Version: "1", OSID: "ubuntu", OSVersion: "18.04", Architecture: "amd64", WebServer: "apache", WebServerVersion: "2.4.29", WebServerBuild: "apache-build", IntegrationMode: model.IntegrationModeExternal, PackageFormat: model.PackageFormatZIP, InstallRoot: "/opt/m-waf"},
	}}}
	module, err := catalog.ResolveModule(inventory)
	if err != nil || module.ID != "custom-apache" {
		t.Fatalf("expected independent module resolution, module=%+v err=%v", module, err)
	}
	if _, _, err := catalog.Resolve(inventory); err == nil {
		t.Fatal("combined resolution must still require an Agent artifact")
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
