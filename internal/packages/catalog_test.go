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

func TestLoadAndResolveExactModule(t *testing.T) {
	root := t.TempDir()
	artifacts := []model.PackageArtifact{
		{ID: "agent", Kind: "agent", Name: "mwaf-agent", Version: "1", OSID: "ubuntu", OSVersion: "24.04", Architecture: "amd64", Path: "packages/agent.deb"},
		{ID: "apache", Kind: "module", Name: "mwaf-modsecurity-apache", Version: "1", OSID: "ubuntu", OSVersion: "24.04", Architecture: "amd64", WebServer: "apache", WebServerVersion: "2.4.58", WebServerBuild: "apache-hash", Path: "packages/apache.deb"},
		{ID: "nginx", Kind: "module", Name: "mwaf-modsecurity-nginx", Version: "1", OSID: "ubuntu", OSVersion: "24.04", Architecture: "amd64", WebServer: "nginx", WebServerVersion: "1.24.0", WebServerBuild: "nginx-hash", Path: "packages/nginx.deb"},
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
	if _, _, err := catalog.Resolve(model.Inventory{OSID: "ubuntu", OSVersion: "24.04", Architecture: "amd64", WebServer: "nginx", WebServerVersion: "1.24.0", WebServerBuild: "different"}); err == nil {
		t.Fatal("expected exact build hash mismatch")
	}
}
