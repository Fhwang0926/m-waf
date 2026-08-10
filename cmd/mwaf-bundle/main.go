package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Fhwang0926/m-waf/internal/model"
	"github.com/Fhwang0926/m-waf/internal/packages"
)

func main() {
	metadataDir := flag.String("metadata", "dist/metadata", "artifact metadata directory")
	packagesDir := flag.String("packages", "dist/packages", "package input directory")
	outputDir := flag.String("output", "dist/bundle", "bundle output directory")
	privateKeyPath := flag.String("key", "", "Ed25519 PKCS#8 private key PEM")
	publicKeyPath := flag.String("public-key-output", "dist/package-signing.pub", "public key output")
	version := flag.String("version", "", "bundle version")
	commit := flag.String("commit", "", "source commit")
	previousBundle := flag.String("previous-bundle", "", "verified previous bundle directory")
	previousPublicKey := flag.String("previous-public-key", "", "previous bundle public key PEM")
	verifyBundle := flag.String("verify-bundle", "", "verify an existing bundle directory and exit")
	verifyPublicKey := flag.String("verify-public-key", "", "public key for -verify-bundle")
	policySourceMetadata := flag.String("policy-source-metadata", "dist/policy-source-metadata", "policy source metadata directory")
	policySources := flag.String("policy-sources", "dist/policy-sources", "policy source input directory")
	flag.Parse()
	if *verifyBundle != "" || *verifyPublicKey != "" {
		if *verifyBundle == "" || *verifyPublicKey == "" {
			fmt.Fprintln(os.Stderr, "verify-bundle and verify-public-key are required together")
			os.Exit(1)
		}
		if _, err := packages.Load(*verifyBundle, *verifyPublicKey, "", false); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if err := assemble(*metadataDir, *packagesDir, *policySourceMetadata, *policySources, *outputDir, *privateKeyPath, *publicKeyPath, *version, *commit, *previousBundle, *previousPublicKey); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func assemble(metadataDir, packagesDir, sourceMetadataDir, sourceInputDir, outputDir, privateKeyPath, publicKeyPath, version, commit, previousBundle, previousPublicKey string) error {
	if version == "" || commit == "" || privateKeyPath == "" {
		return errors.New("version, commit and key are required")
	}
	entries, err := os.ReadDir(metadataDir)
	if err != nil {
		return err
	}
	artifacts := make([]model.PackageArtifact, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(metadataDir, entry.Name()))
		if err != nil {
			return err
		}
		var artifact model.PackageArtifact
		decoder := json.NewDecoder(strings.NewReader(string(raw)))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&artifact); err != nil {
			return fmt.Errorf("decode %s: %w", entry.Name(), err)
		}
		if err := stageArtifact(packagesDir, outputDir, &artifact); err != nil {
			return fmt.Errorf("stage %s: %w", entry.Name(), err)
		}
		if artifact.Kind == "agent" {
			artifact.PolicyFormats = uniqueSorted(append(artifact.PolicyFormats, "conf-v1", "policy-bundle-v2", "policy-bundle-v3"))
		}
		artifacts = append(artifacts, artifact)
	}
	if len(artifacts) < 5 {
		return errors.New("bundle requires an agent and distro/external Apache/Nginx integration artifacts")
	}
	if previousBundle != "" || previousPublicKey != "" {
		if previousBundle == "" || previousPublicKey == "" {
			return errors.New("previous bundle and public key must be provided together")
		}
		artifacts, err = attachPreviousRelease(artifacts, previousBundle, previousPublicKey, outputDir)
		if err != nil {
			return err
		}
	}
	policySources, err := stagePolicySources(sourceMetadataDir, sourceInputDir, outputDir, artifacts)
	if err != nil {
		return err
	}
	if len(policySources) == 0 {
		return errors.New("bundle requires a verified OWASP CRS policy source index")
	}
	hotRuleSet, err := loadHotRuleSet("rules/hot")
	if err != nil {
		return err
	}
	if previousBundle != "" {
		policySources, err = attachPreviousPolicySources(policySources, artifacts, previousBundle, previousPublicKey, outputDir)
		if err != nil {
			return err
		}
	}
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].ID < artifacts[j].ID })
	sort.Slice(policySources, func(i, j int) bool { return policySources[i].ID < policySources[j].ID })
	manifest := model.BundleManifest{
		SchemaVersion: 2, BundleVersion: version, SourceCommit: commit, CreatedAt: time.Now().UTC(),
		ManagerAPIMin: "v1", ManagerAPIMax: "v1", Artifacts: artifacts, PolicySources: policySources, HotRuleSet: hotRuleSet,
	}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	privateKey, publicKey, err := loadPrivateKey(privateKeyPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outputDir, "bundle-manifest.json"), raw, 0o644); err != nil {
		return err
	}
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, raw)) + "\n"
	if err := os.WriteFile(filepath.Join(outputDir, "bundle-manifest.sig"), []byte(signature), 0o644); err != nil {
		return err
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	return os.WriteFile(publicKeyPath, publicPEM, 0o644)
}

func loadHotRuleSet(directory string) (*model.HotRuleSetArtifact, error) {
	raw, err := os.ReadFile(filepath.Join(directory, "manifest.json"))
	if err != nil {
		return nil, fmt.Errorf("read hot-rule manifest: %w", err)
	}
	var item model.HotRuleSetArtifact
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&item); err != nil {
		return nil, fmt.Errorf("decode hot-rule manifest: %w", err)
	}
	rules, err := os.ReadFile(filepath.Join(directory, "rules.conf"))
	if err != nil {
		return nil, fmt.Errorf("read hot rules: %w", err)
	}
	item.Rules = string(rules)
	if err := packages.ValidateHotRuleSet(&item); err != nil {
		return nil, err
	}
	return &item, nil
}

func stagePolicySources(metadataDir, inputDir, outputDir string, artifacts []model.PackageArtifact) ([]model.PolicySourceArtifact, error) {
	entries, err := os.ReadDir(metadataDir)
	if err != nil {
		return nil, err
	}
	items := make([]model.PolicySourceArtifact, 0, len(entries))
	seen := make(map[string]bool)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(metadataDir, entry.Name()))
		if err != nil {
			return nil, err
		}
		var item model.PolicySourceArtifact
		decoder := json.NewDecoder(strings.NewReader(string(raw)))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&item); err != nil {
			return nil, fmt.Errorf("decode policy source %s: %w", entry.Name(), err)
		}
		if seen[item.ID] {
			return nil, fmt.Errorf("duplicate policy source id %q", item.ID)
		}
		seen[item.ID] = true
		if err := stagePolicySourceFile(inputDir, outputDir, &item); err != nil {
			return nil, fmt.Errorf("stage policy source %s: %w", item.ID, err)
		}
		for _, artifact := range artifacts {
			compatibleModule := artifact.Kind == "module" && (artifact.PolicyDelivery == "bundle" && item.ArtifactFormat == "policy-bundle-v3" ||
				strings.TrimPrefix(artifact.CRSVersion, "v") == strings.TrimPrefix(item.Version, "v"))
			if compatibleModule {
				item.CompatiblePackageIDs = append(item.CompatiblePackageIDs, artifact.ID)
			}
		}
		// Agent and web-server module releases are independent. Compatibility is
		// determined by the policy wire format, not by equal package versions.
		for _, artifact := range artifacts {
			if artifact.Kind == "agent" && contains(artifact.PolicyFormats, item.ArtifactFormat) {
				item.CompatiblePackageIDs = append(item.CompatiblePackageIDs, artifact.ID)
			}
		}
		item.CompatiblePackageIDs = uniqueSorted(item.CompatiblePackageIDs)
		if !completePolicySourceCoverage(item.CompatiblePackageIDs, artifacts, item.ArtifactFormat) {
			return nil, fmt.Errorf("policy source %s does not have complete Agent and module package coverage", item.ID)
		}
		items = append(items, item)
	}
	return items, nil
}

func completePolicySourceCoverage(packageIDs []string, artifacts []model.PackageArtifact, policyFormat string) bool {
	allowed := make(map[string]bool, len(packageIDs))
	for _, id := range packageIDs {
		allowed[id] = true
	}
	agent := false
	modules := map[string]bool{}
	for _, artifact := range artifacts {
		if !allowed[artifact.ID] {
			continue
		}
		if artifact.Kind == "agent" && contains(artifact.PolicyFormats, policyFormat) {
			agent = true
		}
		if artifact.Kind == "module" {
			modules[artifact.WebServer+":"+model.NormalizeIntegrationMode(artifact.IntegrationMode)] = true
		}
	}
	return agent && modules["apache:distro"] && modules["apache:external"] && modules["nginx:distro"] && modules["nginx:external"]
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func stagePolicySourceFile(inputDir, outputDir string, item *model.PolicySourceArtifact) error {
	if item.ID == "" || item.Provider != "github" || item.Repository != "https://github.com/coreruleset/coreruleset" || (item.Channel != "stable" && item.Channel != "lts") || !strings.HasPrefix(item.Tag, "v4.") || item.Version == "" || item.Commit == "" || item.TagObjectSHA == "" || !item.TagSignatureVerified || len(item.ArchiveSHA256) != 64 || len(item.IndexSHA256) != 64 {
		return errors.New("official stable or LTS CRS source metadata is incomplete")
	}
	name := filepath.Base(item.IndexPath)
	if name != item.IndexPath {
		return errors.New("policy source index path must be a filename")
	}
	source, err := os.Open(filepath.Join(inputDir, name))
	if err != nil {
		return err
	}
	defer source.Close()
	destinationDir := filepath.Join(outputDir, "policy-sources")
	if err := os.MkdirAll(destinationDir, 0o755); err != nil {
		return err
	}
	destination, err := os.Create(filepath.Join(destinationDir, name))
	if err != nil {
		return err
	}
	hasher := sha256.New()
	size, copyErr := io.Copy(io.MultiWriter(destination, hasher), source)
	closeErr := destination.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if size != item.IndexSize || !strings.EqualFold(hex.EncodeToString(hasher.Sum(nil)), item.IndexSHA256) {
		return errors.New("policy source index changed after metadata generation")
	}
	item.IndexPath = filepath.ToSlash(filepath.Join("policy-sources", name))
	if item.ArchivePath != "" {
		archiveName := filepath.Base(item.ArchivePath)
		if archiveName != item.ArchivePath || item.ArchiveSize <= 0 {
			return errors.New("policy source archive path or size is invalid")
		}
		archiveInput := filepath.Join(inputDir, archiveName)
		archiveOutput := filepath.Join(destinationDir, archiveName)
		if err := copyVerifiedPolicySourceFile(archiveInput, archiveOutput, item.ArchiveSize, item.ArchiveSHA256); err != nil {
			return fmt.Errorf("stage policy source archive: %w", err)
		}
		item.ArchivePath = filepath.ToSlash(filepath.Join("policy-sources", archiveName))
	}
	return nil
}

func copyVerifiedPolicySourceFile(sourcePath, destinationPath string, expectedSize int64, expectedSHA string) error {
	source, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer source.Close()
	destination, err := os.Create(destinationPath)
	if err != nil {
		return err
	}
	hasher := sha256.New()
	size, copyErr := io.Copy(io.MultiWriter(destination, hasher), source)
	closeErr := destination.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if size != expectedSize || !strings.EqualFold(hex.EncodeToString(hasher.Sum(nil)), expectedSHA) {
		return errors.New("policy source archive changed after metadata generation")
	}
	return nil
}

func attachPreviousPolicySources(current []model.PolicySourceArtifact, artifacts []model.PackageArtifact, previousBundle, previousPublicKey, outputDir string) ([]model.PolicySourceArtifact, error) {
	catalog, err := packages.Load(previousBundle, previousPublicKey, "", false)
	if err != nil {
		return nil, fmt.Errorf("verify previous policy sources: %w", err)
	}
	seen := make(map[string]bool, len(current))
	for _, item := range current {
		seen[item.ID] = true
	}
	result := append([]model.PolicySourceArtifact(nil), current...)
	availablePackages := make(map[string]bool, len(artifacts))
	for _, artifact := range artifacts {
		availablePackages[artifact.ID] = true
	}
	for _, item := range catalog.Manifest().PolicySources {
		if seen[item.ID] {
			continue
		}
		source, err := os.Open(filepath.Join(previousBundle, filepath.FromSlash(item.IndexPath)))
		if err != nil {
			return nil, err
		}
		name := filepath.Base(item.IndexPath)
		destinationDir := filepath.Join(outputDir, "policy-sources")
		if err := os.MkdirAll(destinationDir, 0o755); err != nil {
			source.Close()
			return nil, err
		}
		destination, err := os.Create(filepath.Join(destinationDir, name))
		if err != nil {
			source.Close()
			return nil, err
		}
		hasher := sha256.New()
		size, copyErr := io.Copy(io.MultiWriter(destination, hasher), source)
		closeErr := destination.Close()
		if copyErr != nil {
			return nil, copyErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if size != item.IndexSize || !strings.EqualFold(hex.EncodeToString(hasher.Sum(nil)), item.IndexSHA256) {
			return nil, errors.New("previous policy source index changed after verification")
		}
		compatible := item.CompatiblePackageIDs[:0]
		for _, packageID := range item.CompatiblePackageIDs {
			if availablePackages[packageID] {
				compatible = append(compatible, packageID)
			}
		}
		item.CompatiblePackageIDs = compatible
		item.IndexPath = filepath.ToSlash(filepath.Join("policy-sources", name))
		if item.ArchivePath != "" {
			archiveName := filepath.Base(item.ArchivePath)
			if archiveName != filepath.Base(filepath.Clean(item.ArchivePath)) || item.ArchiveSize <= 0 {
				return nil, errors.New("previous policy source archive metadata is invalid")
			}
			if err := copyVerifiedPolicySourceFile(filepath.Join(previousBundle, filepath.FromSlash(item.ArchivePath)), filepath.Join(destinationDir, archiveName), item.ArchiveSize, item.ArchiveSHA256); err != nil {
				return nil, err
			}
			item.ArchivePath = filepath.ToSlash(filepath.Join("policy-sources", archiveName))
		}
		result = append(result, item)
		seen[item.ID] = true
	}
	return result, nil
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func attachPreviousRelease(current []model.PackageArtifact, previousBundle, previousPublicKey, outputDir string) ([]model.PackageArtifact, error) {
	catalog, err := packages.Load(previousBundle, previousPublicKey, "", false)
	if err != nil {
		return nil, fmt.Errorf("verify previous bundle: %w", err)
	}
	previous := catalog.Manifest().Artifacts
	rollbackTargets := make(map[string]bool)
	for _, artifact := range previous {
		if artifact.RollbackID != "" {
			rollbackTargets[artifact.RollbackID] = true
		}
	}
	seen := make(map[string]bool, len(current)*2)
	for _, artifact := range current {
		seen[artifact.ID] = true
	}
	result := append([]model.PackageArtifact(nil), current...)
	for i := range current {
		matches := make([]model.PackageArtifact, 0, 1)
		for _, candidate := range previous {
			if rollbackTargets[candidate.ID] || !sameTarget(current[i], candidate) {
				continue
			}
			matches = append(matches, candidate)
		}
		if len(matches) == 0 {
			// A newly introduced target has no previous package to roll back to.
			continue
		}
		if len(matches) != 1 {
			return nil, fmt.Errorf("previous bundle has %d active matches for %s", len(matches), current[i].ID)
		}
		rollback := matches[0]
		if seen[rollback.ID] {
			return nil, fmt.Errorf("duplicate rollback package id %q", rollback.ID)
		}
		rollback.RollbackID = ""
		if err := stagePreviousArtifact(previousBundle, outputDir, &rollback); err != nil {
			return nil, fmt.Errorf("stage rollback package %s: %w", rollback.ID, err)
		}
		result[i].RollbackID = rollback.ID
		result = append(result, rollback)
		seen[rollback.ID] = true
	}
	return result, nil
}

func sameTarget(current, previous model.PackageArtifact) bool {
	return current.Kind == previous.Kind && current.OSID == previous.OSID && current.OSVersion == previous.OSVersion &&
		current.Architecture == previous.Architecture && current.WebServer == previous.WebServer &&
		current.WebServerBuild == previous.WebServerBuild &&
		model.NormalizeIntegrationMode(current.IntegrationMode) == model.NormalizeIntegrationMode(previous.IntegrationMode) &&
		model.NormalizePackageFormat(current.PackageFormat) == model.NormalizePackageFormat(previous.PackageFormat)
}

func stagePreviousArtifact(previousBundle, outputDir string, artifact *model.PackageArtifact) error {
	source, err := os.Open(filepath.Join(previousBundle, filepath.FromSlash(artifact.Path)))
	if err != nil {
		return err
	}
	defer source.Close()
	name := filepath.Base(artifact.Path)
	destinationDir := filepath.Join(outputDir, "packages")
	if err := os.MkdirAll(destinationDir, 0o755); err != nil {
		return err
	}
	destination, err := os.Create(filepath.Join(destinationDir, name))
	if err != nil {
		return err
	}
	hasher := sha256.New()
	size, copyErr := io.Copy(io.MultiWriter(destination, hasher), source)
	closeErr := destination.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if size != artifact.Size || !strings.EqualFold(hex.EncodeToString(hasher.Sum(nil)), artifact.SHA256) {
		return errors.New("rollback package changed after bundle verification")
	}
	artifact.Path = filepath.ToSlash(filepath.Join("packages", name))
	return nil
}

func stageArtifact(packagesDir, outputDir string, artifact *model.PackageArtifact) error {
	if artifact.ID == "" || artifact.Name == "" || artifact.Version == "" || artifact.Path == "" {
		return errors.New("id, name, version and path are required")
	}
	name := filepath.Base(artifact.Path)
	if name != artifact.Path {
		return errors.New("metadata path must be a package filename")
	}
	source, err := os.Open(filepath.Join(packagesDir, name))
	if err != nil {
		return err
	}
	defer source.Close()
	destinationDir := filepath.Join(outputDir, "packages")
	if err := os.MkdirAll(destinationDir, 0o755); err != nil {
		return err
	}
	destination, err := os.Create(filepath.Join(destinationDir, name))
	if err != nil {
		return err
	}
	hasher := sha256.New()
	size, copyErr := io.Copy(io.MultiWriter(destination, hasher), source)
	closeErr := destination.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	artifact.Path = filepath.ToSlash(filepath.Join("packages", name))
	artifact.Size = size
	artifact.SHA256 = hex.EncodeToString(hasher.Sum(nil))
	return nil
}

func loadPrivateKey(path string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, nil, errors.New("decode bundle signing key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, nil, errors.New("bundle signing key must be Ed25519")
	}
	return privateKey, privateKey.Public().(ed25519.PublicKey), nil
}
