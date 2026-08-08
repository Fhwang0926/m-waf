package manager

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Fhwang0926/m-waf/internal/crsindex"
	"github.com/Fhwang0926/m-waf/internal/crssource"
	"github.com/Fhwang0926/m-waf/internal/model"
)

type runtimePolicySource struct {
	Source      model.PolicySourceArtifact
	Index       crsindex.Index
	ArchivePath string
}

type runtimePolicySourceManifest struct {
	SchemaVersion int                        `json:"schema_version"`
	Source        model.PolicySourceArtifact `json:"source"`
	ArchivePath   string                     `json:"archive_path"`
	IndexPath     string                     `json:"index_path"`
	ImportedAt    time.Time                  `json:"imported_at"`
	Signature     string                     `json:"signature,omitempty"`
}

func (m runtimePolicySourceManifest) signingBytes() ([]byte, error) {
	m.Signature = ""
	return json.Marshal(m)
}

func (s *Server) loadRuntimePolicySources() error {
	root := filepath.Join(s.cfg.ArtifactRoot, "policy-sources")
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	loaded := make(map[string]runtimePolicySource)
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		directory := filepath.Join(root, entry.Name())
		manifestRaw, err := os.ReadFile(filepath.Join(directory, "source.json"))
		if err != nil {
			return fmt.Errorf("read runtime CRS source %s: %w", entry.Name(), err)
		}
		var manifest runtimePolicySourceManifest
		decoder := json.NewDecoder(bytes.NewReader(manifestRaw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&manifest); err != nil {
			return fmt.Errorf("decode runtime CRS source %s: %w", entry.Name(), err)
		}
		signingRaw, err := manifest.signingBytes()
		if err != nil || manifest.SchemaVersion != 1 || manifest.Source.ID != entry.Name() || !s.policySigner.Verify(signingRaw, manifest.Signature) {
			return fmt.Errorf("runtime CRS source %s failed signature verification", entry.Name())
		}
		if filepath.Base(manifest.ArchivePath) != manifest.ArchivePath || filepath.Base(manifest.IndexPath) != manifest.IndexPath {
			return fmt.Errorf("runtime CRS source %s has an unsafe path", entry.Name())
		}
		archivePath := filepath.Join(directory, manifest.ArchivePath)
		archive, err := os.ReadFile(archivePath)
		if err != nil {
			return err
		}
		archiveDigest := sha256.Sum256(archive)
		if !strings.EqualFold(hex.EncodeToString(archiveDigest[:]), manifest.Source.ArchiveSHA256) {
			return fmt.Errorf("runtime CRS source %s archive digest mismatch", entry.Name())
		}
		indexRaw, err := os.ReadFile(filepath.Join(directory, manifest.IndexPath))
		if err != nil {
			return err
		}
		indexDigest := sha256.Sum256(indexRaw)
		if int64(len(indexRaw)) != manifest.Source.IndexSize || !strings.EqualFold(hex.EncodeToString(indexDigest[:]), manifest.Source.IndexSHA256) {
			return fmt.Errorf("runtime CRS source %s index digest mismatch", entry.Name())
		}
		var index crsindex.Index
		decoder = json.NewDecoder(bytes.NewReader(indexRaw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&index); err != nil {
			return err
		}
		if index.Source.Commit != manifest.Source.Commit || index.Source.ArchiveSHA256 != manifest.Source.ArchiveSHA256 {
			return fmt.Errorf("runtime CRS source %s metadata mismatch", entry.Name())
		}
		if !manifest.Source.TagSignatureVerified || manifest.Source.TagObjectSHA == "" {
			// Sources imported before channel-aware signed-tag metadata existed
			// remain on disk for audit and existing policy rollback, but cannot be
			// used to author a new system-policy revision. One legacy directory
			// must not prevent Manager from starting and fetching a replacement.
			s.logger.Warn("legacy_runtime_crs_source_skipped", "source_id", manifest.Source.ID, "reason", "verified annotated tag metadata is missing")
			continue
		}
		manifest.Source.ArchivePath = filepath.ToSlash(filepath.Join("policy-sources", manifest.Source.ID, manifest.ArchivePath))
		manifest.Source.ArchiveSize = int64(len(archive))
		if err := s.store.UpsertCRSReleaseIndex(context.Background(), manifest.Source, index); err != nil {
			return fmt.Errorf("index runtime CRS source %s in database: %w", entry.Name(), err)
		}
		loaded[manifest.Source.ID] = runtimePolicySource{Source: manifest.Source, Index: index, ArchivePath: archivePath}
	}
	s.sourceMu.Lock()
	s.runtimeSources = loaded
	s.sourceMu.Unlock()
	return nil
}

func (s *Server) importRuntimePolicySource(fetched crssource.Fetched) (bool, error) {
	indexRaw, err := json.MarshalIndent(fetched.Index, "", "  ")
	if err != nil {
		return false, err
	}
	indexRaw = append(indexRaw, '\n')
	indexDigest := sha256.Sum256(indexRaw)
	if !strings.EqualFold(hex.EncodeToString(indexDigest[:]), fetched.Source.IndexSHA256) {
		return false, errors.New("CRS index changed before import")
	}
	if existing, _, ok := s.policySource(fetched.Source.ID); ok {
		if existing.Commit != fetched.Source.Commit || !strings.EqualFold(existing.ArchiveSHA256, fetched.Source.ArchiveSHA256) || !strings.EqualFold(existing.IndexSHA256, fetched.Source.IndexSHA256) {
			return false, errors.New("CRS source ID resolves to different immutable content")
		}
		return false, nil
	}
	root := filepath.Join(s.cfg.ArtifactRoot, "policy-sources")
	directory := filepath.Join(root, fetched.Source.ID)
	s.sourceMu.RLock()
	_, exists := s.runtimeSources[fetched.Source.ID]
	s.sourceMu.RUnlock()
	if exists {
		return false, nil
	}
	if err := os.MkdirAll(root, 0o750); err != nil {
		return false, err
	}
	staging, err := os.MkdirTemp(root, ".source-")
	if err != nil {
		return false, err
	}
	defer os.RemoveAll(staging)
	if err := os.Chmod(staging, 0o750); err != nil {
		return false, err
	}
	if err := writeArtifact(filepath.Join(staging, "archive.tar.gz"), fetched.Archive); err != nil {
		return false, err
	}
	if err := writeArtifact(filepath.Join(staging, "index.json"), indexRaw); err != nil {
		return false, err
	}
	fetched.Source.IndexPath = filepath.ToSlash(filepath.Join("policy-sources", fetched.Source.ID, "index.json"))
	fetched.Source.IndexSize = int64(len(indexRaw))
	fetched.Source.ArchivePath = filepath.ToSlash(filepath.Join("policy-sources", fetched.Source.ID, "archive.tar.gz"))
	fetched.Source.ArchiveSize = int64(len(fetched.Archive))
	manifest := runtimePolicySourceManifest{
		SchemaVersion: 1, Source: fetched.Source, ArchivePath: "archive.tar.gz", IndexPath: "index.json", ImportedAt: time.Now().UTC(),
	}
	signingRaw, err := manifest.signingBytes()
	if err != nil {
		return false, err
	}
	_, manifest.Signature = s.policySigner.Sign(signingRaw)
	manifestRaw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return false, err
	}
	if err := writeArtifact(filepath.Join(staging, "source.json"), append(manifestRaw, '\n')); err != nil {
		return false, err
	}
	if err := os.Rename(staging, directory); err != nil {
		if _, statErr := os.Stat(directory); statErr == nil {
			if loadErr := s.loadRuntimePolicySources(); loadErr != nil {
				return false, loadErr
			}
			if _, _, recovered := s.runtimePolicySource(fetched.Source.ID); recovered {
				return false, nil
			}
			return false, errors.New("existing CRS source directory could not be recovered")
		}
		return false, err
	}
	if err := s.store.UpsertCRSReleaseIndex(context.Background(), fetched.Source, fetched.Index); err != nil {
		return false, err
	}
	s.sourceMu.Lock()
	s.runtimeSources[fetched.Source.ID] = runtimePolicySource{Source: fetched.Source, Index: fetched.Index, ArchivePath: filepath.Join(directory, "archive.tar.gz")}
	s.sourceMu.Unlock()
	return true, nil
}

func (s *Server) allPolicySources() []model.PolicySourceArtifact {
	items := make(map[string]model.PolicySourceArtifact)
	if s.catalog != nil {
		for _, source := range s.catalog.PolicySources() {
			items[source.ID] = source
		}
	}
	s.sourceMu.RLock()
	for id, source := range s.runtimeSources {
		items[id] = source.Source
	}
	s.sourceMu.RUnlock()
	result := make([]model.PolicySourceArtifact, 0, len(items))
	for _, item := range items {
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool { return newerCRSVersion(result[i].Version, result[j].Version) })
	return result
}

func (s *Server) lastCRSSourceSyncAt() time.Time {
	s.sourceMu.RLock()
	defer s.sourceMu.RUnlock()
	return s.lastCRSSync
}

func (s *Server) syncCRSReleaseIndexes(ctx context.Context) error {
	var syncErrors []error
	for _, source := range s.allPolicySources() {
		if !source.TagSignatureVerified || source.TagObjectSHA == "" {
			continue
		}
		_, index, ok := s.policySource(source.ID)
		if !ok {
			syncErrors = append(syncErrors, fmt.Errorf("CRS source %s index is unavailable", source.ID))
			continue
		}
		if err := s.store.UpsertCRSReleaseIndex(ctx, source, index); err != nil {
			syncErrors = append(syncErrors, fmt.Errorf("index CRS source %s: %w", source.ID, err))
		}
	}
	return errors.Join(syncErrors...)
}

func (s *Server) runtimePolicySource(id string) (model.PolicySourceArtifact, crsindex.Index, bool) {
	s.sourceMu.RLock()
	defer s.sourceMu.RUnlock()
	item, ok := s.runtimeSources[strings.TrimSpace(id)]
	return item.Source, item.Index, ok
}

func (s *Server) policySourceFiles(id string) (map[string][]byte, error) {
	s.sourceMu.RLock()
	item, ok := s.runtimeSources[strings.TrimSpace(id)]
	s.sourceMu.RUnlock()
	if !ok {
		if s.catalog != nil {
			return s.catalog.PolicySourceFiles(strings.TrimSpace(id))
		}
		return nil, errors.New("self-contained CRS source is unavailable")
	}
	archive, err := os.Open(item.ArchivePath)
	if err != nil {
		return nil, err
	}
	defer archive.Close()
	return crsindex.PolicyFilesFromArchive(archive)
}
