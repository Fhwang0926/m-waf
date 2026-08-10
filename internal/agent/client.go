package agent

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Fhwang0926/m-waf/internal/config"
	"github.com/Fhwang0926/m-waf/internal/model"
	"github.com/Fhwang0926/m-waf/internal/protocol"
)

type Client struct {
	cfg      config.Agent
	mu       sync.RWMutex
	http     *http.Client
	serverID string
}

func NewClient(cfg config.Agent) (*Client, error) {
	client := &Client{cfg: cfg}
	if raw, err := os.ReadFile(filepath.Join(cfg.StateDirectory, "server-id")); err == nil {
		client.serverID = strings.TrimSpace(string(raw))
	}
	httpClient, err := client.buildHTTPClient(client.serverID != "")
	if err != nil {
		return nil, err
	}
	client.http = httpClient
	return client, nil
}

func (c *Client) ServerID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.serverID
}

func (c *Client) Enroll(ctx context.Context, inventory model.Inventory) error {
	if c.ServerID() != "" {
		return nil
	}
	if c.cfg.EnrollmentToken == "" {
		return errors.New("enrollment token is required")
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{Organization: []string{"M-WAF Agent"}, CommonName: c.cfg.ServerName}}, privateKey)
	if err != nil {
		return err
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	request := protocol.EnrollRequest{Token: c.cfg.EnrollmentToken, Name: c.cfg.ServerName, CSRPEM: string(csrPEM), Inventory: inventory}
	var response protocol.EnrollResponse
	if err := c.doJSON(ctx, http.MethodPost, protocol.EnrollPath, request, &response); err != nil {
		return err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return err
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	if err := atomicWrite(c.cfg.PrivateKey, privatePEM, 0o600); err != nil {
		return err
	}
	if err := atomicWrite(c.cfg.Certificate, []byte(response.CertificatePEM), 0o640); err != nil {
		return err
	}
	if response.PolicyPublicKey == "" {
		return errors.New("manager did not return policy signing public key")
	}
	if err := atomicWrite(c.cfg.PolicyPublicKey, []byte(response.PolicyPublicKey), 0o640); err != nil {
		return err
	}
	if err := atomicWrite(filepath.Join(c.cfg.StateDirectory, "server-id"), []byte(response.ServerID+"\n"), 0o640); err != nil {
		return err
	}
	httpClient, err := c.buildHTTPClient(true)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.serverID = response.ServerID
	c.http = httpClient
	c.mu.Unlock()
	if c.cfg.EnrollmentFile != "" {
		_ = os.Remove(c.cfg.EnrollmentFile)
	}
	return nil
}

func (c *Client) CertificateExpiresWithin(window time.Duration) (bool, time.Time, error) {
	certificate, err := loadLeafCertificate(c.cfg.Certificate)
	if err != nil {
		return false, time.Time{}, err
	}
	return time.Until(certificate.NotAfter) <= window, certificate.NotAfter, nil
}

func (c *Client) RenewCertificate(ctx context.Context) (time.Time, error) {
	keyPEM, err := os.ReadFile(c.cfg.PrivateKey)
	if err != nil {
		return time.Time{}, err
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return time.Time{}, errors.New("decode agent private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse agent private key: %w", err)
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return time.Time{}, errors.New("agent private key cannot sign")
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{Organization: []string{"M-WAF Agent"}, CommonName: c.ServerID()}}, signer)
	if err != nil {
		return time.Time{}, err
	}
	request := protocol.CertificateRenewRequest{CSRPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))}
	var response protocol.CertificateRenewResponse
	if err := c.doJSON(ctx, http.MethodPost, protocol.CertificateRenewPath, request, &response); err != nil {
		return time.Time{}, err
	}
	if response.CertificatePEM == "" || response.ExpiresAt.IsZero() {
		return time.Time{}, errors.New("manager returned an invalid renewed certificate")
	}
	if _, err := tls.X509KeyPair([]byte(response.CertificatePEM), keyPEM); err != nil {
		return time.Time{}, fmt.Errorf("renewed certificate does not match agent key: %w", err)
	}
	if err := atomicWrite(c.cfg.Certificate, []byte(response.CertificatePEM), 0o640); err != nil {
		return time.Time{}, err
	}
	httpClient, err := c.buildHTTPClient(true)
	if err != nil {
		return time.Time{}, err
	}
	c.mu.Lock()
	previous := c.http
	c.http = httpClient
	c.mu.Unlock()
	previous.CloseIdleConnections()
	return response.ExpiresAt, nil
}

func (c *Client) Heartbeat(ctx context.Context, heartbeat model.HeartbeatRequest) error {
	return c.doJSON(ctx, http.MethodPost, protocol.HeartbeatPath, heartbeat, nil)
}

func (c *Client) DesiredState(ctx context.Context) (model.DesiredState, error) {
	var state model.DesiredState
	err := c.doJSON(ctx, http.MethodGet, protocol.DesiredStatePath, nil, &state)
	return state, err
}

func (c *Client) SendEvents(ctx context.Context, batch model.EventBatch) error {
	token := strings.TrimSpace(c.cfg.EventVerificationToken)
	if token == "" {
		return errors.New("event verification token is required")
	}
	headers := make(http.Header)
	headers.Set(protocol.EventVerificationHeader, token)
	return c.doJSONWithHeaders(ctx, http.MethodPost, protocol.EventBatchPath, batch, nil, headers)
}

func (c *Client) SendPolicyResult(ctx context.Context, revisionID, status, detail string) error {
	return c.doJSON(ctx, http.MethodPost, protocol.PolicyResultPath(revisionID), protocol.DeploymentResult{Status: status, Detail: detail}, nil)
}

func (c *Client) SendPackageResult(ctx context.Context, deploymentID, status, detail string) error {
	return c.doJSON(ctx, http.MethodPost, protocol.PackageResultPath(deploymentID), protocol.DeploymentResult{Status: status, Detail: detail}, nil)
}

func (c *Client) NextCommand(ctx context.Context) (model.AgentCommand, error) {
	var command model.AgentCommand
	err := c.doJSON(ctx, http.MethodGet, protocol.NextCommandPath, nil, &command)
	return command, err
}

func (c *Client) SendCommandResult(ctx context.Context, commandID, status, detail string) error {
	return c.doJSON(ctx, http.MethodPost, protocol.CommandResultPath(commandID), protocol.DeploymentResult{Status: status, Detail: detail}, nil)
}

func (c *Client) EnsurePolicyPublicKey(ctx context.Context) error {
	if _, err := os.Stat(c.cfg.PolicyPublicKey); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	raw, err := c.doBytes(ctx, protocol.PolicyKeyPath, 64<<10)
	if err != nil {
		return err
	}
	return atomicWrite(c.cfg.PolicyPublicKey, raw, 0o640)
}

func (c *Client) DownloadPolicy(ctx context.Context, path string) ([]byte, error) {
	if !strings.HasPrefix(path, protocol.PolicyArtifactPrefix) {
		return nil, errors.New("invalid policy artifact path")
	}
	return c.doBytes(ctx, path, protocol.AgentV1.PolicyArtifactLimit)
}

func (c *Client) DownloadBasePolicy(ctx context.Context, path string) ([]byte, error) {
	if !strings.HasPrefix(path, protocol.PolicyBaseArtifactPrefix) {
		return nil, errors.New("invalid base policy artifact path")
	}
	return c.doBytes(ctx, path, protocol.AgentV1.PolicyArtifactLimit)
}

func (c *Client) DownloadPackage(ctx context.Context, item model.PackageDownload, destination string) error {
	if item.ID == "" || !strings.HasPrefix(item.URL, protocol.AgentPackagePrefix) || item.Size < 1 || item.Size > protocol.AgentV1.PackageLimit {
		return errors.New("invalid package download")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.cfg.ManagerURL, "/")+item.URL, nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		return fmt.Errorf("manager returned %s: %s", resp.Status, strings.TrimSpace(string(limited)))
	}
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(resp.Body, item.Size+1))
	closeErr := file.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if written != item.Size {
		return fmt.Errorf("package size mismatch: got %d want %d", written, item.Size)
	}
	if !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), item.SHA256) {
		return errors.New("package checksum mismatch")
	}
	return nil
}

func (c *Client) doBytes(ctx context.Context, path string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.cfg.ManagerURL, "/")+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		return nil, fmt.Errorf("manager returned %s: %s", resp.Status, strings.TrimSpace(string(limited)))
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, errors.New("manager response exceeds size limit")
	}
	return raw, nil
}

func (c *Client) doJSON(ctx context.Context, method, path string, requestBody, responseBody any) error {
	return c.doJSONWithHeaders(ctx, method, path, requestBody, responseBody, nil)
}

func (c *Client) doJSONWithHeaders(ctx context.Context, method, path string, requestBody, responseBody any, headers http.Header) error {
	var body io.Reader
	if requestBody != nil {
		raw, err := json.Marshal(requestBody)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.cfg.ManagerURL, "/")+path, body)
	if err != nil {
		return err
	}
	if requestBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for name, values := range headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		return fmt.Errorf("manager returned %s: %s", resp.Status, strings.TrimSpace(string(limited)))
	}
	if responseBody != nil {
		if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(responseBody); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) httpClient() *http.Client {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.http
}

func (c *Client) buildHTTPClient(withCertificate bool) (*http.Client, error) {
	caPEM, err := os.ReadFile(c.cfg.CACertificate)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("append manager CA certificate")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	if withCertificate {
		certificate, err := tls.LoadX509KeyPair(c.cfg.Certificate, c.cfg.PrivateKey)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig, MaxIdleConns: 4, MaxIdleConnsPerHost: 4, IdleConnTimeout: 90 * time.Second, ResponseHeaderTimeout: 30 * time.Second}
	return &http.Client{Transport: transport, Timeout: 2 * time.Minute}, nil
}

func loadLeafCertificate(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("decode agent certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return certificate, nil
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".mwaf-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
