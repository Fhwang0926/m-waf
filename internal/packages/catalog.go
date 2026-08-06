package packages

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Fhwang0926/m-waf/internal/model"
)

const (
	manifestName  = "bundle-manifest.json"
	signatureName = "bundle-manifest.sig"
)

type Catalog struct {
	root     string
	raw      []byte
	manifest model.BundleManifest
	byID     map[string]model.PackageArtifact
}

func Load(root, publicKeyPath string, expectedCommit string, allowUnsigned bool) (*Catalog, error) {
	raw, err := os.ReadFile(filepath.Join(root, manifestName))
	if err != nil {
		return nil, fmt.Errorf("read bundle manifest: %w", err)
	}

	if err := verifyManifest(raw, filepath.Join(root, signatureName), publicKeyPath, allowUnsigned); err != nil {
		return nil, err
	}

	var manifest model.BundleManifest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("decode bundle manifest: %w", err)
	}
	if manifest.SchemaVersion != 1 {
		return nil, fmt.Errorf("unsupported bundle schema version %d", manifest.SchemaVersion)
	}
	if manifest.BundleVersion == "" || manifest.SourceCommit == "" {
		return nil, errors.New("bundle version and source commit are required")
	}
	if expectedCommit != "" && expectedCommit != "unknown" && manifest.SourceCommit != expectedCommit {
		return nil, fmt.Errorf("bundle commit %q does not match manager commit %q", manifest.SourceCommit, expectedCommit)
	}

	catalog := &Catalog{root: root, raw: raw, manifest: manifest, byID: make(map[string]model.PackageArtifact, len(manifest.Artifacts))}
	for _, artifact := range manifest.Artifacts {
		if err := catalog.validateArtifact(artifact); err != nil {
			return nil, err
		}
		if _, exists := catalog.byID[artifact.ID]; exists {
			return nil, fmt.Errorf("duplicate package id %q", artifact.ID)
		}
		catalog.byID[artifact.ID] = artifact
	}
	return catalog, nil
}

func (c *Catalog) Manifest() model.BundleManifest { return c.manifest }

func (c *Catalog) ManifestSHA256() string {
	sum := sha256.Sum256(c.raw)
	return hex.EncodeToString(sum[:])
}

func (c *Catalog) Resolve(inventory model.Inventory) (model.PackageArtifact, model.PackageArtifact, error) {
	rollbackTargets := make(map[string]bool)
	for _, artifact := range c.manifest.Artifacts {
		if artifact.RollbackID != "" {
			rollbackTargets[artifact.RollbackID] = true
		}
	}
	var agent *model.PackageArtifact
	var module *model.PackageArtifact
	for i := range c.manifest.Artifacts {
		artifact := c.manifest.Artifacts[i]
		if rollbackTargets[artifact.ID] || !matchesBase(artifact, inventory) {
			continue
		}
		switch artifact.Kind {
		case "agent":
			if agent != nil {
				return model.PackageArtifact{}, model.PackageArtifact{}, errors.New("package catalog has multiple matching agent packages")
			}
			agent = &artifact
		case "module":
			if artifact.WebServer != inventory.WebServer {
				continue
			}
			if model.NormalizeIntegrationMode(artifact.IntegrationMode) != model.NormalizeIntegrationMode(inventory.IntegrationMode) {
				continue
			}
			if artifact.WebServerVersion != "" && artifact.WebServerVersion != inventory.WebServerVersion {
				continue
			}
			if artifact.WebServerBuild != "" && artifact.WebServerBuild != inventory.WebServerBuild {
				continue
			}
			if module != nil {
				return model.PackageArtifact{}, model.PackageArtifact{}, errors.New("package catalog has multiple matching module packages")
			}
			module = &artifact
		}
	}
	if agent == nil {
		return model.PackageArtifact{}, model.PackageArtifact{}, fmt.Errorf("no agent package for %s %s %s", inventory.OSID, inventory.OSVersion, inventory.Architecture)
	}
	if module == nil {
		return model.PackageArtifact{}, model.PackageArtifact{}, fmt.Errorf("no %s module package for %s %s %s", inventory.WebServer, inventory.OSID, inventory.OSVersion, inventory.Architecture)
	}
	return *agent, *module, nil
}

// ResolveCRS returns a signed Agent/module pair that contains the requested CRS
// version. It includes the single retained rollback release in the search.
func (c *Catalog) ResolveCRS(inventory model.Inventory, crsVersion string) (model.PackageArtifact, model.PackageArtifact, error) {
	rollbackTargets := make(map[string]bool)
	for _, artifact := range c.manifest.Artifacts {
		if artifact.RollbackID != "" {
			rollbackTargets[artifact.RollbackID] = true
		}
	}
	var currentModules []model.PackageArtifact
	var rollbackModules []model.PackageArtifact
	for _, artifact := range c.manifest.Artifacts {
		if artifact.Kind != "module" || !matchesBase(artifact, inventory) || artifact.WebServer != inventory.WebServer {
			continue
		}
		if model.NormalizeIntegrationMode(artifact.IntegrationMode) != model.NormalizeIntegrationMode(inventory.IntegrationMode) || strings.TrimPrefix(artifact.CRSVersion, "v") != strings.TrimPrefix(crsVersion, "v") {
			continue
		}
		if artifact.WebServerVersion != "" && artifact.WebServerVersion != inventory.WebServerVersion {
			continue
		}
		if artifact.WebServerBuild != "" && artifact.WebServerBuild != inventory.WebServerBuild {
			continue
		}
		if rollbackTargets[artifact.ID] {
			rollbackModules = append(rollbackModules, artifact)
		} else {
			currentModules = append(currentModules, artifact)
		}
	}
	modules := currentModules
	if len(modules) == 0 {
		modules = rollbackModules
	}
	if len(modules) != 1 {
		return model.PackageArtifact{}, model.PackageArtifact{}, fmt.Errorf("expected one preferred %s module package with CRS %s, found %d", inventory.WebServer, crsVersion, len(modules))
	}
	module := modules[0]
	var agents []model.PackageArtifact
	for _, artifact := range c.manifest.Artifacts {
		if artifact.Kind == "agent" && matchesBase(artifact, inventory) && artifact.Version == module.Version && rollbackTargets[artifact.ID] == rollbackTargets[module.ID] {
			agents = append(agents, artifact)
		}
	}
	if len(agents) != 1 {
		return model.PackageArtifact{}, model.PackageArtifact{}, fmt.Errorf("expected one agent package for module release %s, found %d", module.Version, len(agents))
	}
	return agents[0], module, nil
}

func (c *Catalog) Artifact(id string) (model.PackageArtifact, bool) {
	artifact, ok := c.byID[id]
	return artifact, ok
}

func (c *Catalog) Rollback(agentID, moduleID string) (model.PackageArtifact, model.PackageArtifact, error) {
	agent, ok := c.byID[agentID]
	if !ok || agent.Kind != "agent" || agent.RollbackID == "" {
		return model.PackageArtifact{}, model.PackageArtifact{}, errors.New("agent rollback package is unavailable")
	}
	module, ok := c.byID[moduleID]
	if !ok || module.Kind != "module" || module.RollbackID == "" {
		return model.PackageArtifact{}, model.PackageArtifact{}, errors.New("module rollback package is unavailable")
	}
	agentRollback, ok := c.byID[agent.RollbackID]
	if !ok || agentRollback.Kind != "agent" {
		return model.PackageArtifact{}, model.PackageArtifact{}, errors.New("agent rollback target is invalid")
	}
	moduleRollback, ok := c.byID[module.RollbackID]
	if !ok || moduleRollback.Kind != "module" {
		return model.PackageArtifact{}, model.PackageArtifact{}, errors.New("module rollback target is invalid")
	}
	return agentRollback, moduleRollback, nil
}

func (c *Catalog) Open(id string) (model.PackageArtifact, *os.File, error) {
	artifact, ok := c.byID[id]
	if !ok {
		return model.PackageArtifact{}, nil, os.ErrNotExist
	}
	f, err := os.Open(filepath.Join(c.root, filepath.FromSlash(artifact.Path)))
	if err != nil {
		return model.PackageArtifact{}, nil, err
	}
	return artifact, f, nil
}

func (c *Catalog) validateArtifact(artifact model.PackageArtifact) error {
	if artifact.ID == "" || artifact.Name == "" || artifact.Version == "" || artifact.SHA256 == "" || artifact.Path == "" {
		return fmt.Errorf("package artifact %q has missing required fields", artifact.ID)
	}
	if artifact.Kind != "agent" && artifact.Kind != "module" {
		return fmt.Errorf("package artifact %q has invalid kind %q", artifact.ID, artifact.Kind)
	}
	if artifact.Kind == "module" {
		mode := model.NormalizeIntegrationMode(artifact.IntegrationMode)
		if mode != model.IntegrationModeDistro && mode != model.IntegrationModeExternal {
			return fmt.Errorf("package artifact %q has invalid integration mode %q", artifact.ID, artifact.IntegrationMode)
		}
	}
	clean := filepath.Clean(filepath.FromSlash(artifact.Path))
	if filepath.IsAbs(clean) || clean == "." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || clean == ".." {
		return fmt.Errorf("package artifact %q has unsafe path", artifact.ID)
	}
	path := filepath.Join(c.root, clean)
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat package artifact %q: %w", artifact.ID, err)
	}
	if !info.Mode().IsRegular() || info.Size() != artifact.Size {
		return fmt.Errorf("package artifact %q size mismatch", artifact.ID)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	if !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), artifact.SHA256) {
		return fmt.Errorf("package artifact %q checksum mismatch", artifact.ID)
	}
	return nil
}

func matchesBase(artifact model.PackageArtifact, inventory model.Inventory) bool {
	return artifact.OSID == inventory.OSID &&
		artifact.OSVersion == inventory.OSVersion &&
		artifact.Architecture == inventory.Architecture
}

func verifyManifest(raw []byte, signaturePath, publicKeyPath string, allowUnsigned bool) error {
	sigText, sigErr := os.ReadFile(signaturePath)
	keyText, keyErr := os.ReadFile(publicKeyPath)
	if sigErr != nil || keyErr != nil {
		if allowUnsigned {
			return nil
		}
		return errors.New("signed bundle requires manifest signature and public key")
	}
	block, _ := pem.Decode(keyText)
	if block == nil {
		return errors.New("decode package signing public key PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse package signing public key: %w", err)
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return errors.New("package signing key must be Ed25519")
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigText)))
	if err != nil {
		return fmt.Errorf("decode bundle manifest signature: %w", err)
	}
	if !ed25519.Verify(publicKey, raw, signature) {
		return errors.New("bundle manifest signature verification failed")
	}
	return nil
}
