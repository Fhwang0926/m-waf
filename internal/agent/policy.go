package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Fhwang0926/m-waf/internal/config"
	"github.com/Fhwang0926/m-waf/internal/model"
	"github.com/Fhwang0926/m-waf/internal/policybundle"
)

var policyRevisionName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

type PolicyApplier struct {
	cfg config.Agent
}

func NewPolicyApplier(cfg config.Agent) *PolicyApplier { return &PolicyApplier{cfg: cfg} }

func (p *PolicyApplier) Apply(parent context.Context, webServer string, state model.DesiredState, artifact []byte) error {
	if state.Mode != "DetectionOnly" && state.Mode != "On" {
		return fmt.Errorf("unsupported policy mode %q", state.Mode)
	}
	limit := 1 << 20
	if state.ArtifactFormat == policybundle.Format {
		limit = 4 << 20
	} else if state.ArtifactFormat == policybundle.FormatV3 {
		limit = 64 << 20
	}
	if len(artifact) == 0 || len(artifact) > limit {
		return errors.New("policy artifact size is invalid")
	}
	hash := sha256.Sum256(artifact)
	if !strings.EqualFold(hex.EncodeToString(hash[:]), state.SHA256) {
		return errors.New("policy artifact checksum mismatch")
	}
	if err := p.verifySignature(artifact, state.Signature); err != nil {
		return err
	}
	if state.ArtifactFormat == policybundle.Format || state.ArtifactFormat == policybundle.FormatV3 {
		return p.applyBundle(parent, webServer, state, artifact)
	}
	if state.ArtifactFormat != "" && state.ArtifactFormat != "conf-v1" {
		return fmt.Errorf("unsupported policy artifact format %q", state.ArtifactFormat)
	}
	previous, err := os.ReadFile(p.cfg.PolicyPath)
	if err != nil {
		return fmt.Errorf("read current policy: %w", err)
	}
	if string(previous) == string(artifact) {
		return nil
	}
	if err := atomicWrite(filepath.Join(p.cfg.StateDirectory, "previous-policy.conf"), previous, 0o600); err != nil {
		return fmt.Errorf("backup current policy: %w", err)
	}
	if err := atomicWrite(p.cfg.PolicyPath, artifact, 0o640); err != nil {
		return fmt.Errorf("write policy: %w", err)
	}
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	if err := p.testAndReload(ctx, webServer); err != nil {
		if rollbackErr := atomicWrite(p.cfg.PolicyPath, previous, 0o640); rollbackErr != nil {
			return fmt.Errorf("apply failed: %v; rollback write failed: %w", err, rollbackErr)
		}
		rollbackCtx, rollbackCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer rollbackCancel()
		if rollbackErr := p.testAndReload(rollbackCtx, webServer); rollbackErr != nil {
			return fmt.Errorf("apply failed: %v; rollback reload failed: %w", err, rollbackErr)
		}
		return fmt.Errorf("policy rejected and rolled back: %w", err)
	}
	return nil
}

func (p *PolicyApplier) applyBundle(parent context.Context, webServer string, state model.DesiredState, artifact []byte) error {
	if !policyRevisionName.MatchString(state.RevisionID) {
		return errors.New("policy revision id is unsafe")
	}
	manifest, files, err := policybundle.Parse(artifact)
	if err != nil {
		return err
	}
	activePath := filepath.Clean(filepath.Dir(p.cfg.PolicyPath))
	if activePath == "." || activePath == string(filepath.Separator) {
		return errors.New("policy active directory is unsafe")
	}
	revisionsPath := filepath.Join(filepath.Dir(activePath), "revisions")
	if err := os.MkdirAll(revisionsPath, 0o750); err != nil {
		return fmt.Errorf("create policy revisions directory: %w", err)
	}
	stagingPath, err := os.MkdirTemp(revisionsPath, ".staging-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stagingPath)
	for name, content := range files {
		if err := atomicWrite(filepath.Join(stagingPath, name), content, 0o640); err != nil {
			return fmt.Errorf("stage policy bundle: %w", err)
		}
	}
	manifestRaw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := atomicWrite(filepath.Join(stagingPath, "manifest.json"), append(manifestRaw, '\n'), 0o640); err != nil {
		return fmt.Errorf("stage policy manifest: %w", err)
	}
	if err := atomicWrite(filepath.Join(stagingPath, "main.conf"), []byte("# Compatibility entry for rollback packages. Managed by mwaf-agent.\n"), 0o640); err != nil {
		return fmt.Errorf("stage rollback compatibility policy: %w", err)
	}
	revisionPath := filepath.Join(revisionsPath, state.RevisionID)
	if _, err := os.Lstat(revisionPath); err == nil {
		return errors.New("policy revision directory already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(stagingPath, revisionPath); err != nil {
		return fmt.Errorf("publish policy revision directory: %w", err)
	}
	previousTarget, err := p.prepareActiveLink(activePath, revisionsPath)
	if err != nil {
		_ = os.RemoveAll(revisionPath)
		return err
	}
	if err := replaceSymlink(activePath, revisionPath); err != nil {
		_ = os.RemoveAll(revisionPath)
		if restoreErr := replaceSymlink(activePath, previousTarget); restoreErr != nil {
			return fmt.Errorf("activate policy revision: %v; restore previous revision: %w", err, restoreErr)
		}
		return fmt.Errorf("activate policy revision: %w", err)
	}
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	if err := p.testAndReload(ctx, webServer); err != nil {
		if rollbackErr := replaceSymlink(activePath, previousTarget); rollbackErr != nil {
			return fmt.Errorf("apply failed: %v; rollback switch failed: %w", err, rollbackErr)
		}
		rollbackCtx, rollbackCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer rollbackCancel()
		if rollbackErr := p.testAndReload(rollbackCtx, webServer); rollbackErr != nil {
			return fmt.Errorf("apply failed: %v; rollback reload failed: %w", err, rollbackErr)
		}
		_ = os.RemoveAll(revisionPath)
		return fmt.Errorf("policy bundle rejected and rolled back: %w", err)
	}
	_ = atomicWrite(filepath.Join(p.cfg.StateDirectory, "previous-policy-revision"), []byte(previousTarget+"\n"), 0o600)
	return nil
}

func (p *PolicyApplier) prepareActiveLink(activePath, revisionsPath string) (string, error) {
	info, err := os.Lstat(activePath)
	if err != nil {
		return "", fmt.Errorf("inspect active policy: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(activePath)
		if err != nil {
			return "", err
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(activePath), target)
		}
		return filepath.Clean(target), nil
	}
	if !info.IsDir() {
		return "", errors.New("active policy path must be a directory or symlink")
	}
	legacyPath := filepath.Join(revisionsPath, "legacy-"+strconv.FormatInt(time.Now().UTC().Unix(), 10))
	if err := os.Rename(activePath, legacyPath); err != nil {
		return "", fmt.Errorf("migrate legacy active policy: %w", err)
	}
	return legacyPath, nil
}

func replaceSymlink(activePath, target string) error {
	if target == "" || !filepath.IsAbs(target) {
		return errors.New("policy symlink target must be absolute")
	}
	temporary := activePath + ".next"
	_ = os.Remove(temporary)
	if err := os.Symlink(target, temporary); err != nil {
		return err
	}
	if err := os.Rename(temporary, activePath); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}

func (p *PolicyApplier) verifySignature(artifact []byte, encoded string) error {
	raw, err := os.ReadFile(p.cfg.PolicyPublicKey)
	if err != nil {
		return fmt.Errorf("read policy signing public key: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return errors.New("decode policy signing public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return errors.New("policy signing key must be Ed25519")
	}
	signature, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("decode policy signature: %w", err)
	}
	if !ed25519.Verify(publicKey, artifact, signature) {
		return errors.New("policy signature verification failed")
	}
	return nil
}

func (p *PolicyApplier) testAndReload(ctx context.Context, webServer string) error {
	var commands [][]string
	switch webServer {
	case "apache":
		binary := p.cfg.WebServerBinary
		if binary == "" {
			binary = "apachectl"
			if _, err := exec.LookPath(binary); err != nil {
				binary = "httpd"
			}
		}
		commands = [][]string{{binary, "configtest"}, {binary, "graceful"}}
	case "nginx":
		binary := p.cfg.WebServerBinary
		if binary == "" {
			binary = "nginx"
		}
		commands = [][]string{{binary, "-t"}, {binary, "-s", "reload"}}
	default:
		return errors.New("unsupported web server")
	}
	for _, command := range commands {
		output, err := exec.CommandContext(ctx, command[0], command[1:]...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s failed: %s: %w", strings.Join(command, " "), truncateOutput(output), err)
		}
	}
	return nil
}

func truncateOutput(raw []byte) string {
	const limit = 2048
	if len(raw) > limit {
		raw = raw[:limit]
	}
	return strings.TrimSpace(string(raw))
}
