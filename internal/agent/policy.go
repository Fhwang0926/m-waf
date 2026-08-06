package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Fhwang0926/m-waf/internal/config"
	"github.com/Fhwang0926/m-waf/internal/model"
)

type PolicyApplier struct {
	cfg config.Agent
}

func NewPolicyApplier(cfg config.Agent) *PolicyApplier { return &PolicyApplier{cfg: cfg} }

func (p *PolicyApplier) Apply(parent context.Context, webServer string, state model.DesiredState, artifact []byte) error {
	if state.Mode != "DetectionOnly" && state.Mode != "On" {
		return fmt.Errorf("unsupported policy mode %q", state.Mode)
	}
	if len(artifact) == 0 || len(artifact) > 1<<20 {
		return errors.New("policy artifact size is invalid")
	}
	hash := sha256.Sum256(artifact)
	if !strings.EqualFold(hex.EncodeToString(hash[:]), state.SHA256) {
		return errors.New("policy artifact checksum mismatch")
	}
	if err := p.verifySignature(artifact, state.Signature); err != nil {
		return err
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
