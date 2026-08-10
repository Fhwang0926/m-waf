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
	"regexp"
	"strconv"
	"strings"

	"github.com/Fhwang0926/m-waf/internal/crsindex"
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
	sources  map[string]model.PolicySourceArtifact
	indexes  map[string]crsindex.Index
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
	if manifest.SchemaVersion != 1 && manifest.SchemaVersion != 2 {
		return nil, fmt.Errorf("unsupported bundle schema version %d", manifest.SchemaVersion)
	}
	if manifest.SchemaVersion == 2 && len(manifest.PolicySources) == 0 {
		return nil, errors.New("bundle schema v2 requires policy_sources")
	}
	if manifest.BundleVersion == "" || manifest.SourceCommit == "" {
		return nil, errors.New("bundle version and source commit are required")
	}
	if err := ValidateHotRuleSet(manifest.HotRuleSet); err != nil {
		return nil, err
	}
	if expectedCommit != "" && expectedCommit != "unknown" && manifest.SourceCommit != expectedCommit {
		return nil, fmt.Errorf("bundle commit %q does not match manager commit %q", manifest.SourceCommit, expectedCommit)
	}

	catalog := &Catalog{
		root: root, raw: raw, manifest: manifest, byID: make(map[string]model.PackageArtifact, len(manifest.Artifacts)),
		sources: make(map[string]model.PolicySourceArtifact, len(manifest.PolicySources)), indexes: make(map[string]crsindex.Index, len(manifest.PolicySources)),
	}
	for _, artifact := range manifest.Artifacts {
		if err := catalog.validateArtifact(artifact); err != nil {
			return nil, err
		}
		if _, exists := catalog.byID[artifact.ID]; exists {
			return nil, fmt.Errorf("duplicate package id %q", artifact.ID)
		}
		catalog.byID[artifact.ID] = artifact
	}
	for _, source := range manifest.PolicySources {
		index, err := catalog.validatePolicySource(source)
		if err != nil {
			return nil, err
		}
		if _, exists := catalog.sources[source.ID]; exists {
			return nil, fmt.Errorf("duplicate policy source id %q", source.ID)
		}
		catalog.sources[source.ID] = source
		catalog.indexes[source.ID] = index
	}
	return catalog, nil
}

func (c *Catalog) Manifest() model.BundleManifest { return c.manifest }

func (c *Catalog) HotRuleSet() *model.HotRuleSetArtifact {
	if c.manifest.HotRuleSet == nil {
		return nil
	}
	copy := *c.manifest.HotRuleSet
	return &copy
}

func (c *Catalog) PolicySources() []model.PolicySourceArtifact {
	return append([]model.PolicySourceArtifact(nil), c.manifest.PolicySources...)
}

func (c *Catalog) PolicySource(id string) (model.PolicySourceArtifact, crsindex.Index, bool) {
	source, ok := c.sources[id]
	if !ok {
		return model.PolicySourceArtifact{}, crsindex.Index{}, false
	}
	return source, c.indexes[id], true
}

func (c *Catalog) PolicySourceFiles(id string) (map[string][]byte, error) {
	source, ok := c.sources[id]
	if !ok || source.ArchivePath == "" || source.ArchiveSize <= 0 {
		return nil, errors.New("self-contained CRS source archive is unavailable")
	}
	clean := filepath.Clean(filepath.FromSlash(source.ArchivePath))
	if filepath.IsAbs(clean) || clean == "." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || clean == ".." {
		return nil, errors.New("policy source archive path is unsafe")
	}
	file, err := os.Open(filepath.Join(c.root, clean))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	hasher := sha256.New()
	raw, err := io.ReadAll(io.TeeReader(io.LimitReader(file, source.ArchiveSize+1), hasher))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) != source.ArchiveSize || !strings.EqualFold(hex.EncodeToString(hasher.Sum(nil)), source.ArchiveSHA256) {
		return nil, errors.New("policy source archive hash or size mismatch")
	}
	return crsindex.PolicyFilesFromArchive(bytes.NewReader(raw))
}

func (c *Catalog) ManifestSHA256() string {
	sum := sha256.Sum256(c.raw)
	return hex.EncodeToString(sum[:])
}

func (c *Catalog) Resolve(inventory model.Inventory) (model.PackageArtifact, model.PackageArtifact, error) {
	agent, err := c.ResolveAgent(inventory)
	if err != nil {
		return model.PackageArtifact{}, model.PackageArtifact{}, err
	}
	module, err := c.ResolveModule(inventory)
	if err != nil {
		return model.PackageArtifact{}, model.PackageArtifact{}, err
	}
	return agent, module, nil
}

// ResolveModule resolves the web-server integration independently from the
// Agent. This keeps UI compatibility diagnostics accurate when only one of the
// two artifacts is present in the active bundle.
func (c *Catalog) ResolveModule(inventory model.Inventory) (model.PackageArtifact, error) {
	rollbackTargets := make(map[string]bool)
	for _, artifact := range c.manifest.Artifacts {
		if artifact.RollbackID != "" {
			rollbackTargets[artifact.RollbackID] = true
		}
	}
	var module *model.PackageArtifact
	desiredModuleFormat := model.PackageFormatDEB
	if inventory.InstallationMode == model.InstallationModeCustomZIP {
		desiredModuleFormat = model.PackageFormatZIP
	}
	for i := range c.manifest.Artifacts {
		artifact := c.manifest.Artifacts[i]
		if rollbackTargets[artifact.ID] || !matchesBase(artifact, inventory) {
			continue
		}
		if artifact.Kind == "module" {
			if model.NormalizePackageFormat(artifact.PackageFormat) != desiredModuleFormat {
				continue
			}
			if artifact.WebServer != inventory.WebServer {
				continue
			}
			if model.NormalizeIntegrationMode(artifact.IntegrationMode) != model.NormalizeIntegrationMode(inventory.IntegrationMode) {
				continue
			}
			if desiredModuleFormat == model.PackageFormatZIP {
				if inventory.WebServerVersion == "" || artifact.WebServerVersion == "" || artifact.WebServerVersion != inventory.WebServerVersion || inventory.WebServerBuild == "" || artifact.WebServerBuild == "" || artifact.WebServerBuild != inventory.WebServerBuild || artifact.InstallRoot != "/opt/m-waf" {
					continue
				}
			} else {
				if artifact.WebServerVersion != "" && artifact.WebServerVersion != inventory.WebServerVersion {
					continue
				}
				if artifact.WebServerBuild != "" && artifact.WebServerBuild != inventory.WebServerBuild {
					continue
				}
			}
			if module != nil {
				return model.PackageArtifact{}, errors.New("package catalog has multiple matching module packages")
			}
			module = &artifact
		}
	}
	if module == nil {
		return model.PackageArtifact{}, fmt.Errorf("no %s module package for %s %s %s", inventory.WebServer, inventory.OSID, inventory.OSVersion, inventory.Architecture)
	}
	return *module, nil
}

func (c *Catalog) ResolveAgent(inventory model.Inventory) (model.PackageArtifact, error) {
	rollbackTargets := make(map[string]bool)
	for _, artifact := range c.manifest.Artifacts {
		if artifact.RollbackID != "" {
			rollbackTargets[artifact.RollbackID] = true
		}
	}
	var matches []model.PackageArtifact
	for _, artifact := range c.manifest.Artifacts {
		if artifact.Kind == "agent" && !rollbackTargets[artifact.ID] && matchesBase(artifact, inventory) {
			matches = append(matches, artifact)
		}
	}
	if len(matches) != 1 {
		return model.PackageArtifact{}, fmt.Errorf("expected one Agent package for %s %s %s, found %d", inventory.OSID, inventory.OSVersion, inventory.Architecture, len(matches))
	}
	return matches[0], nil
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
	desiredModuleFormat := model.PackageFormatDEB
	if inventory.InstallationMode == model.InstallationModeCustomZIP {
		desiredModuleFormat = model.PackageFormatZIP
	}
	for _, artifact := range c.manifest.Artifacts {
		if artifact.Kind != "module" || !matchesBase(artifact, inventory) || artifact.WebServer != inventory.WebServer {
			continue
		}
		if model.NormalizePackageFormat(artifact.PackageFormat) != desiredModuleFormat {
			continue
		}
		if model.NormalizeIntegrationMode(artifact.IntegrationMode) != model.NormalizeIntegrationMode(inventory.IntegrationMode) {
			continue
		}
		if artifact.PolicyDelivery != "bundle" && strings.TrimPrefix(artifact.CRSVersion, "v") != strings.TrimPrefix(crsVersion, "v") {
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
	agent, err := c.ResolveAgent(inventory)
	if err != nil {
		return model.PackageArtifact{}, model.PackageArtifact{}, err
	}
	return agent, module, nil
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

func (c *Catalog) RollbackAgent(agentID string) (model.PackageArtifact, error) {
	agent, ok := c.byID[agentID]
	if !ok || agent.Kind != "agent" || agent.RollbackID == "" {
		return model.PackageArtifact{}, errors.New("agent rollback package is unavailable")
	}
	rollback, ok := c.byID[agent.RollbackID]
	if !ok || rollback.Kind != "agent" {
		return model.PackageArtifact{}, errors.New("agent rollback target is invalid")
	}
	return rollback, nil
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
	format := model.NormalizePackageFormat(artifact.PackageFormat)
	if format != model.PackageFormatDEB && format != model.PackageFormatZIP {
		return fmt.Errorf("package artifact %q has unsupported format %q", artifact.ID, format)
	}
	if artifact.Kind == "agent" && format != model.PackageFormatDEB {
		return fmt.Errorf("Agent artifact %q must use deb format", artifact.ID)
	}
	if format == model.PackageFormatZIP && (artifact.Kind != "module" || artifact.IntegrationMode != model.IntegrationModeExternal || artifact.WebServer == "" || artifact.WebServerVersion == "" || artifact.WebServerBuild == "" || artifact.RuntimeABI == "" || artifact.InstallRoot != "/opt/m-waf") {
		return fmt.Errorf("custom module artifact %q requires external integration, exact web-server version and build hash, runtime ABI, and /opt/m-waf install root", artifact.ID)
	}
	if artifact.Kind == "module" {
		mode := model.NormalizeIntegrationMode(artifact.IntegrationMode)
		if mode != model.IntegrationModeDistro && mode != model.IntegrationModeExternal {
			return fmt.Errorf("package artifact %q has invalid integration mode %q", artifact.ID, artifact.IntegrationMode)
		}
		if artifact.PolicyDelivery != "" && artifact.PolicyDelivery != "embedded" && artifact.PolicyDelivery != "bundle" {
			return fmt.Errorf("package artifact %q has invalid policy delivery %q", artifact.ID, artifact.PolicyDelivery)
		}
		if artifact.PolicyDelivery == "bundle" && artifact.RuntimeABI == "" {
			return fmt.Errorf("package artifact %q requires runtime_abi for bundle policy delivery", artifact.ID)
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

func (c *Catalog) validatePolicySource(source model.PolicySourceArtifact) (crsindex.Index, error) {
	if source.ID == "" || source.Provider != "github" || source.Repository != "https://github.com/coreruleset/coreruleset" || (source.Channel != "stable" && source.Channel != "lts") || !strings.HasPrefix(source.Tag, "v4.") || source.Version == "" || source.Commit == "" || len(source.ArchiveSHA256) != 64 || len(source.IndexSHA256) != 64 || source.IndexSize <= 0 {
		return crsindex.Index{}, fmt.Errorf("policy source %q is incomplete", source.ID)
	}
	clean := filepath.Clean(filepath.FromSlash(source.IndexPath))
	if filepath.IsAbs(clean) || clean == "." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || clean == ".." {
		return crsindex.Index{}, fmt.Errorf("policy source %q has unsafe index path", source.ID)
	}
	file, err := os.Open(filepath.Join(c.root, clean))
	if err != nil {
		return crsindex.Index{}, fmt.Errorf("open policy source %q: %w", source.ID, err)
	}
	defer file.Close()
	hasher := sha256.New()
	limited := io.LimitReader(file, source.IndexSize+1)
	raw, err := io.ReadAll(io.TeeReader(limited, hasher))
	if err != nil {
		return crsindex.Index{}, err
	}
	if int64(len(raw)) != source.IndexSize || !strings.EqualFold(hex.EncodeToString(hasher.Sum(nil)), source.IndexSHA256) {
		return crsindex.Index{}, fmt.Errorf("policy source %q index hash or size mismatch", source.ID)
	}
	var index crsindex.Index
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&index); err != nil {
		return crsindex.Index{}, fmt.Errorf("decode policy source %q: %w", source.ID, err)
	}
	if index.SchemaVersion != crsindex.SchemaVersion || index.Source.Provider != source.Provider || index.Source.Repository != source.Repository || index.Source.Channel != source.Channel || strings.TrimPrefix(index.Source.Version, "v") != strings.TrimPrefix(source.Version, "v") || index.Source.Tag != source.Tag || index.Source.Commit != source.Commit || !strings.EqualFold(index.Source.ArchiveSHA256, source.ArchiveSHA256) || index.Statistics.RuleCount != len(index.Rules) {
		return crsindex.Index{}, fmt.Errorf("policy source %q metadata does not match its index", source.ID)
	}
	if source.ArtifactFormat == "policy-bundle-v3" {
		if source.TagObjectSHA == "" || !source.TagSignatureVerified {
			return crsindex.Index{}, fmt.Errorf("policy source %q does not have a verified annotated tag", source.ID)
		}
		if source.ArchivePath == "" || source.ArchiveSize <= 0 {
			return crsindex.Index{}, fmt.Errorf("policy source %q is missing its immutable archive", source.ID)
		}
		archivePath := filepath.Clean(filepath.FromSlash(source.ArchivePath))
		if filepath.IsAbs(archivePath) || archivePath == "." || strings.HasPrefix(archivePath, ".."+string(filepath.Separator)) || archivePath == ".." {
			return crsindex.Index{}, fmt.Errorf("policy source %q has unsafe archive path", source.ID)
		}
		archive, err := os.Open(filepath.Join(c.root, archivePath))
		if err != nil {
			return crsindex.Index{}, fmt.Errorf("open policy source archive %q: %w", source.ID, err)
		}
		hasher := sha256.New()
		written, copyErr := io.Copy(hasher, io.LimitReader(archive, source.ArchiveSize+1))
		closeErr := archive.Close()
		if copyErr != nil {
			return crsindex.Index{}, copyErr
		}
		if closeErr != nil {
			return crsindex.Index{}, closeErr
		}
		if written != source.ArchiveSize || !strings.EqualFold(hex.EncodeToString(hasher.Sum(nil)), source.ArchiveSHA256) {
			return crsindex.Index{}, fmt.Errorf("policy source %q archive hash or size mismatch", source.ID)
		}
	}
	for _, packageID := range source.CompatiblePackageIDs {
		if _, exists := c.byID[packageID]; !exists {
			return crsindex.Index{}, fmt.Errorf("policy source %q references missing package %q", source.ID, packageID)
		}
	}
	return index, nil
}

func matchesBase(artifact model.PackageArtifact, inventory model.Inventory) bool {
	return artifact.OSID == inventory.OSID &&
		artifact.OSVersion == inventory.OSVersion &&
		artifact.Architecture == inventory.Architecture
}

var hotRuleIDPattern = regexp.MustCompile(`(?:^|[, \t"])(?:id):([0-9]+)(?:[,"]|$)`)

func ValidateHotRuleSet(item *model.HotRuleSetArtifact) error {
	if item == nil {
		return nil
	}
	if item.SchemaVersion != 1 || item.Version == "" || item.RuleIDMin != 10000 || item.RuleIDMax != 39999 || len(item.SHA256) != 64 {
		return errors.New("signed hot-rule set metadata is invalid")
	}
	digest := sha256.Sum256([]byte(item.Rules))
	if !strings.EqualFold(hex.EncodeToString(digest[:]), item.SHA256) {
		return errors.New("signed hot-rule set digest mismatch")
	}
	if strings.ContainsAny(item.Rules, "\x00\r") {
		return errors.New("signed hot-rule set must use normalized LF text")
	}
	seen := make(map[int]bool)
	for lineNumber, rawLine := range strings.Split(item.Rules, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(line) > 16<<10 || !strings.HasPrefix(line, "SecRule ") && !strings.HasPrefix(line, "SecAction ") {
			return fmt.Errorf("signed hot-rule line %d is not a normalized SecRule or SecAction", lineNumber+1)
		}
		allMatches := hotRuleIDPattern.FindAllStringSubmatch(line, -1)
		if len(allMatches) != 1 || len(allMatches[0]) != 2 {
			return fmt.Errorf("signed hot-rule line %d requires one Rule ID", lineNumber+1)
		}
		id, err := strconv.Atoi(allMatches[0][1])
		if err != nil || id < item.RuleIDMin || id > item.RuleIDMax || seen[id] {
			return fmt.Errorf("signed hot-rule line %d has an invalid or duplicate Rule ID", lineNumber+1)
		}
		seen[id] = true
	}
	return nil
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
