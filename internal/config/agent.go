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
	ManagerURL                 string        `json:"manager_url"`
	ServerName                 string        `json:"server_name"`
	WebServer                  string        `json:"web_server,omitempty"`
	EnrollmentToken            string        `json:"enrollment_token,omitempty"`
	EnrollmentFile             string        `json:"enrollment_token_file,omitempty"`
	CACertificate              string        `json:"ca_certificate"`
	Certificate                string        `json:"certificate"`
	PrivateKey                 string        `json:"private_key"`
	PolicyPublicKey            string        `json:"policy_public_key,omitempty"`
	PolicyPath                 string        `json:"policy_path,omitempty"`
	StateDirectory             string        `json:"state_directory"`
	SpoolDirectory             string        `json:"spool_directory"`
	AuditLog                   string        `json:"audit_log"`
	Heartbeat                  time.Duration `json:"-"`
	HeartbeatText              string        `json:"heartbeat_interval"`
	CertificateRenewBefore     time.Duration `json:"-"`
	CertificateRenewBeforeText string        `json:"certificate_renew_before,omitempty"`
	EventFlushInterval         time.Duration `json:"-"`
	EventFlushIntervalText     string        `json:"event_flush_interval,omitempty"`
	EventRetryMax              time.Duration `json:"-"`
	EventRetryMaxText          string        `json:"event_retry_max,omitempty"`
	EventBatchSize             int           `json:"event_batch_size,omitempty"`
	EventBatchesPerFlush       int           `json:"event_batches_per_flush,omitempty"`
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
	if cfg.CertificateRenewBeforeText == "" {
		cfg.CertificateRenewBefore = 30 * 24 * time.Hour
	} else if cfg.CertificateRenewBefore, err = time.ParseDuration(cfg.CertificateRenewBeforeText); err != nil {
		return Agent{}, fmt.Errorf("parse certificate renew before: %w", err)
	}
	if cfg.EventFlushIntervalText == "" {
		cfg.EventFlushInterval = 2 * time.Second
	} else if cfg.EventFlushInterval, err = time.ParseDuration(cfg.EventFlushIntervalText); err != nil {
		return Agent{}, fmt.Errorf("parse event flush interval: %w", err)
	}
	if cfg.EventRetryMaxText == "" {
		cfg.EventRetryMax = time.Minute
	} else if cfg.EventRetryMax, err = time.ParseDuration(cfg.EventRetryMaxText); err != nil {
		return Agent{}, fmt.Errorf("parse event retry max: %w", err)
	}
	if cfg.EventBatchSize == 0 {
		cfg.EventBatchSize = 500
	}
	if cfg.EventBatchesPerFlush == 0 {
		cfg.EventBatchesPerFlush = 20
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
	if c.CertificateRenewBefore < 24*time.Hour || c.CertificateRenewBefore > 60*24*time.Hour {
		return errors.New("certificate_renew_before must be between 24h and 1440h")
	}
	if c.EventFlushInterval < time.Second || c.EventRetryMax < c.EventFlushInterval {
		return errors.New("event_flush_interval must be at least 1s and event_retry_max must not be shorter")
	}
	if c.EventBatchSize < 1 || c.EventBatchSize > 500 || c.EventBatchesPerFlush < 1 || c.EventBatchesPerFlush > 100 {
		return errors.New("event batch size must be 1..500 and batches per flush must be 1..100")
	}
	return nil
}
