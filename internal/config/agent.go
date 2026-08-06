package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

type Agent struct {
	ManagerURL      string        `json:"manager_url"`
	ServerName      string        `json:"server_name"`
	WebServer       string        `json:"web_server,omitempty"`
	EnrollmentToken string        `json:"enrollment_token,omitempty"`
	EnrollmentFile  string        `json:"enrollment_token_file,omitempty"`
	CACertificate   string        `json:"ca_certificate"`
	Certificate     string        `json:"certificate"`
	PrivateKey      string        `json:"private_key"`
	PolicyPublicKey string        `json:"policy_public_key,omitempty"`
	PolicyPath      string        `json:"policy_path,omitempty"`
	StateDirectory  string        `json:"state_directory"`
	SpoolDirectory  string        `json:"spool_directory"`
	AuditLog        string        `json:"audit_log"`
	Heartbeat       time.Duration `json:"-"`
	HeartbeatText   string        `json:"heartbeat_interval"`
}

func LoadAgent(path string) (Agent, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Agent{}, fmt.Errorf("read agent config: %w", err)
	}
	var cfg Agent
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return Agent{}, fmt.Errorf("decode agent config: %w", err)
	}
	if cfg.HeartbeatText == "" {
		cfg.Heartbeat = 30 * time.Second
	} else {
		cfg.Heartbeat, err = time.ParseDuration(cfg.HeartbeatText)
		if err != nil {
			return Agent{}, fmt.Errorf("parse heartbeat interval: %w", err)
		}
	}
	if cfg.StateDirectory == "" {
		cfg.StateDirectory = "/var/lib/mwaf-agent"
	}
	if cfg.SpoolDirectory == "" {
		cfg.SpoolDirectory = cfg.StateDirectory + "/spool"
	}
	if cfg.PolicyPublicKey == "" {
		cfg.PolicyPublicKey = cfg.StateDirectory + "/policy-signing.pub"
	}
	if cfg.PolicyPath == "" {
		cfg.PolicyPath = "/etc/mwaf/active/main.conf"
	}
	if err := cfg.Validate(); err != nil {
		return Agent{}, err
	}
	if cfg.EnrollmentFile != "" && cfg.EnrollmentToken == "" {
		token, err := os.ReadFile(cfg.EnrollmentFile)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return Agent{}, fmt.Errorf("read enrollment token: %w", err)
			}
			if _, certErr := os.Stat(cfg.Certificate); certErr != nil {
				return Agent{}, fmt.Errorf("read enrollment token: %w", err)
			}
		} else {
			cfg.EnrollmentToken = strings.TrimSpace(string(token))
		}
	}
	return cfg, nil
}

func (c Agent) Validate() error {
	if c.ManagerURL == "" || c.CACertificate == "" || c.Certificate == "" || c.PrivateKey == "" {
		return errors.New("manager_url, ca_certificate, certificate and private_key are required")
	}
	if c.Heartbeat < 5*time.Second {
		return errors.New("heartbeat_interval must be at least 5s")
	}
	return nil
}
