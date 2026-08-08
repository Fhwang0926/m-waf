package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Fhwang0926/m-waf/internal/crsindex"
	"github.com/Fhwang0926/m-waf/internal/model"
)

func main() {
	archivePath := flag.String("archive", "", "verified OWASP CRS release archive")
	outputPath := flag.String("output", "", "CRS rule index output")
	metadataPath := flag.String("metadata-output", "", "policy source metadata output")
	repository := flag.String("repository", "https://github.com/coreruleset/coreruleset", "source repository")
	channel := flag.String("channel", "stable", "source channel")
	version := flag.String("version", "", "CRS version without v prefix")
	tag := flag.String("tag", "", "verified Git tag")
	commit := flag.String("commit", "", "verified Git commit")
	tagObjectSHA := flag.String("tag-object-sha", "", "verified annotated Git tag object")
	tagVerified := flag.Bool("tag-signature-verified", false, "annotated Git tag signature was verified")
	archiveSHA256 := flag.String("archive-sha256", "", "verified archive SHA-256")
	flag.Parse()
	if err := run(*archivePath, *outputPath, *metadataPath, *repository, *channel, *version, *tag, *commit, *tagObjectSHA, *tagVerified, *archiveSHA256); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(archivePath, outputPath, metadataPath, repository, channel, version, tag, commit, tagObjectSHA string, tagVerified bool, archiveSHA256 string) error {
	if archivePath == "" || outputPath == "" || metadataPath == "" || version == "" || tag == "" || commit == "" || len(tagObjectSHA) != 40 || !tagVerified || len(archiveSHA256) != 64 {
		return errors.New("archive, output, metadata-output, version, tag, commit, verified tag object and archive-sha256 are required")
	}
	if err := verifyArchiveSHA256(archivePath, archiveSHA256); err != nil {
		return err
	}
	archive, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer archive.Close()
	index, err := crsindex.BuildFromArchive(archive, crsindex.Source{
		Provider: "github", Repository: repository, Channel: channel, Version: strings.TrimPrefix(version, "v"), Tag: tag, Commit: commit, ArchiveSHA256: archiveSHA256,
	})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(outputPath, raw, 0o644); err != nil {
		return err
	}
	file, err := os.Open(outputPath)
	if err != nil {
		return err
	}
	hasher := sha256.New()
	size, err := io.Copy(hasher, file)
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.MkdirAll(filepath.Dir(metadataPath), 0o755); err != nil {
		return err
	}
	shortCommit := commit
	if len(shortCommit) > 12 {
		shortCommit = shortCommit[:12]
	}
	metadata := model.PolicySourceArtifact{
		ID: "owasp-crs-" + channel + "-" + strings.TrimPrefix(version, "v") + "-" + shortCommit, Provider: "github", Repository: repository, Channel: channel,
		Version: strings.TrimPrefix(version, "v"), Tag: tag, Commit: commit, TagObjectSHA: tagObjectSHA, TagSignatureVerified: tagVerified, ArchivePath: filepath.Base(archivePath), ArchiveSHA256: strings.ToLower(archiveSHA256),
		IndexPath: filepath.Base(outputPath), IndexSize: size, IndexSHA256: hex.EncodeToString(hasher.Sum(nil)),
		ArtifactFormat: "policy-bundle-v3",
	}
	archiveInfo, err := os.Stat(archivePath)
	if err != nil {
		return err
	}
	metadata.ArchiveSize = archiveInfo.Size()
	metadataRaw, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(metadataPath, append(metadataRaw, '\n'), 0o644)
}

func verifyArchiveSHA256(path, expected string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	hasher := sha256.New()
	_, copyErr := io.Copy(hasher, file)
	closeErr := file.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	actual := hex.EncodeToString(hasher.Sum(nil))
	if !strings.EqualFold(actual, expected) {
		return fmt.Errorf("CRS archive SHA-256 mismatch: got %s", actual)
	}
	return nil
}
