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
)

func main() {
	metadataDir := flag.String("metadata", "dist/metadata", "artifact metadata directory")
	packagesDir := flag.String("packages", "dist/packages", "package input directory")
	outputDir := flag.String("output", "dist/bundle", "bundle output directory")
	privateKeyPath := flag.String("key", "", "Ed25519 PKCS#8 private key PEM")
	publicKeyPath := flag.String("public-key-output", "dist/package-signing.pub", "public key output")
	version := flag.String("version", "", "bundle version")
	commit := flag.String("commit", "", "source commit")
	flag.Parse()
	if err := assemble(*metadataDir, *packagesDir, *outputDir, *privateKeyPath, *publicKeyPath, *version, *commit); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func assemble(metadataDir, packagesDir, outputDir, privateKeyPath, publicKeyPath, version, commit string) error {
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
	if len(artifacts) < 3 {
		return errors.New("bundle requires an agent and both Apache/Nginx module artifacts")
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
