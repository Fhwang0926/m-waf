package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Fhwang0926/m-waf/internal/config"
	"github.com/Fhwang0926/m-waf/internal/model"
)

type Client struct {
	cfg      config.Agent
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

func (c *Client) ServerID() string { return c.serverID }

func (c *Client) Enroll(ctx context.Context, inventory model.Inventory) error {
	if c.serverID != "" {
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
	request := model.EnrollRequest{Token: c.cfg.EnrollmentToken, Name: c.cfg.ServerName, CSRPEM: string(csrPEM), Inventory: inventory}
	var response model.EnrollResponse
	if err := c.doJSON(ctx, http.MethodPost, "/agent/v1/enroll", request, &response); err != nil {
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
	c.serverID = response.ServerID
	httpClient, err := c.buildHTTPClient(true)
	if err != nil {
		return err
	}
	c.http = httpClient
	if c.cfg.EnrollmentFile != "" {
		_ = os.Remove(c.cfg.EnrollmentFile)
	}
	return nil
}

func (c *Client) Heartbeat(ctx context.Context, heartbeat model.HeartbeatRequest) error {
	return c.doJSON(ctx, http.MethodPost, "/agent/v1/heartbeat", heartbeat, nil)
}

func (c *Client) DesiredState(ctx context.Context) (model.DesiredState, error) {
	var state model.DesiredState
	err := c.doJSON(ctx, http.MethodGet, "/agent/v1/desired-state", nil, &state)
	return state, err
}

func (c *Client) SendEvents(ctx context.Context, batch model.EventBatch) error {
	return c.doJSON(ctx, http.MethodPost, "/agent/v1/events/batch", batch, nil)
}

func (c *Client) EnsurePolicyPublicKey(ctx context.Context) error {
	if _, err := os.Stat(c.cfg.PolicyPublicKey); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	raw, err := c.doBytes(ctx, "/agent/v1/policy-key", 64<<10)
	if err != nil {
		return err
	}
	return atomicWrite(c.cfg.PolicyPublicKey, raw, 0o640)
}

func (c *Client) DownloadPolicy(ctx context.Context, path string) ([]byte, error) {
	if !strings.HasPrefix(path, "/agent/v1/artifacts/") {
		return nil, errors.New("invalid policy artifact path")
	}
	return c.doBytes(ctx, path, 1<<20)
}

func (c *Client) doBytes(ctx context.Context, path string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.cfg.ManagerURL, "/")+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
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
	resp, err := c.http.Do(req)
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
