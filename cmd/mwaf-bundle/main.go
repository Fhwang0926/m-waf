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
	flag.Parse()
	if err := assemble(*metadataDir, *packagesDir, *outputDir, *privateKeyPath, *publicKeyPath, *version, *commit, *previousBundle, *previousPublicKey); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func assemble(metadataDir, packagesDir, outputDir, privateKeyPath, publicKeyPath, version, commit, previousBundle, previousPublicKey string) error {
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
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].ID < artifacts[j].ID })
	manifest := model.BundleManifest{
		SchemaVersion: 1, BundleVersion: version, SourceCommit: commit, CreatedAt: time.Now().UTC(),
		ManagerAPIMin: "v1", ManagerAPIMax: "v1", Artifacts: artifacts,
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
		model.NormalizeIntegrationMode(current.IntegrationMode) == model.NormalizeIntegrationMode(previous.IntegrationMode)
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
