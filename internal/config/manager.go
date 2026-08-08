package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
)

type Manager struct {
	AdminAddr           string
	PublicURL           string
	DevLiveReload       bool
	DBDSN               string
	DBMigrate           bool
	BundleRoot          string
	BundlePublicKey     string
	BundleRequired      bool
	BundleAllowUnsigned bool
	SessionKey          []byte
	TLSCertificate      string
	TLSPrivateKey       string
	AgentCACertificate  string
	AgentCAPrivateKey   string
	PolicySigningKey    string
	PolicySigningPublic string
	ArtifactRoot        string
	EnrollmentTTL       time.Duration
	EventRetention      time.Duration
	CleanupInterval     time.Duration
	PolicySyncInterval  time.Duration
	CRSSyncInterval     time.Duration
	CRSGitHubToken      string
	CRSLTSLine          string
	ShutdownTimeout     time.Duration
}

func LoadManager() (Manager, error) {
	dbPassword, err := secret("MWAF_DB_PASSWORD", "MWAF_DB_PASSWORD_FILE", "")
	if err != nil {
		return Manager{}, err
	}
	sessionKey, err := secret("MWAF_SESSION_KEY", "MWAF_SESSION_KEY_FILE", "")
	if err != nil {
		return Manager{}, err
	}

	dbConfig := mysql.NewConfig()
	dbConfig.User = value("MWAF_DB_USER", "mwaf")
	dbConfig.Passwd = dbPassword
	dbConfig.Net = "tcp"
	dbConfig.Addr = value("MWAF_DB_HOST", "127.0.0.1") + ":" + value("MWAF_DB_PORT", "3306")
	dbConfig.DBName = value("MWAF_DB_NAME", "mwaf")
	dbConfig.ParseTime = true
	dbConfig.MultiStatements = true
	dbConfig.Params = map[string]string{
		"charset":   "utf8mb4",
		"collation": "utf8mb4_unicode_ci",
		"time_zone": "'+00:00'",
	}
	dbConfig.Timeout = 5 * time.Second
	dbConfig.ReadTimeout = 10 * time.Second
	dbConfig.WriteTimeout = 10 * time.Second

	cfg := Manager{
		AdminAddr:           value("MWAF_ADMIN_ADDR", ":8443"),
		PublicURL:           strings.TrimRight(value("MWAF_PUBLIC_URL", "https://127.0.0.1:8443"), "/"),
		DevLiveReload:       boolean("MWAF_DEV_LIVE_RELOAD", false),
		DBDSN:               dbConfig.FormatDSN(),
		DBMigrate:           boolean("MWAF_DB_MIGRATE", false),
		BundleRoot:          value("MWAF_BUNDLE_ROOT", "/opt/mwaf/bundles/current"),
		BundlePublicKey:     value("MWAF_BUNDLE_PUBLIC_KEY", "/etc/mwaf-manager/package-signing.pub"),
		BundleRequired:      boolean("MWAF_BUNDLE_REQUIRED", true),
		BundleAllowUnsigned: boolean("MWAF_BUNDLE_ALLOW_UNSIGNED", false),
		SessionKey:          []byte(sessionKey),
		TLSCertificate:      value("MWAF_TLS_CERT", "/etc/mwaf-manager/tls/server.crt"),
		TLSPrivateKey:       value("MWAF_TLS_KEY", "/etc/mwaf-manager/tls/server.key"),
		AgentCACertificate:  value("MWAF_AGENT_CA_CERT", "/etc/mwaf-manager/pki/agent-ca.crt"),
		AgentCAPrivateKey:   value("MWAF_AGENT_CA_KEY", "/etc/mwaf-manager/pki/agent-ca.key"),
		PolicySigningKey:    value("MWAF_POLICY_SIGNING_KEY", "/etc/mwaf-manager/pki/policy-signing.key"),
		PolicySigningPublic: value("MWAF_POLICY_SIGNING_PUBLIC", "/etc/mwaf-manager/pki/policy-signing.pub"),
		ArtifactRoot:        value("MWAF_ARTIFACT_ROOT", "/var/lib/mwaf-manager/artifacts"),
		EnrollmentTTL:       duration("MWAF_ENROLLMENT_TTL", 15*time.Minute),
		EventRetention:      duration("MWAF_EVENT_RETENTION", 30*24*time.Hour),
		CleanupInterval:     duration("MWAF_CLEANUP_INTERVAL", time.Hour),
		PolicySyncInterval:  duration("MWAF_POLICY_SYNC_INTERVAL", 15*time.Minute),
		CRSSyncInterval:     duration("MWAF_CRS_SYNC_INTERVAL", 24*time.Hour),
		CRSGitHubToken:      strings.TrimSpace(os.Getenv("MWAF_CRS_GITHUB_TOKEN")),
		CRSLTSLine:          value("MWAF_CRS_LTS_LINE", "4.25"),
		ShutdownTimeout:     duration("MWAF_SHUTDOWN_TIMEOUT", 15*time.Second),
	}
	if override := os.Getenv("MWAF_DB_DSN"); override != "" {
		cfg.DBDSN = override
	}
	if err := cfg.Validate(); err != nil {
		return Manager{}, err
	}
	return cfg, nil
}

func (c Manager) Validate() error {
	if err := validateListenAddress("MWAF_ADMIN_ADDR", c.AdminAddr); err != nil {
		return err
	}
	if len(c.SessionKey) < 32 {
		return errors.New("MWAF_SESSION_KEY_FILE must contain at least 32 characters")
	}
	if c.DBDSN == "" {
		return errors.New("database DSN is required")
	}
	if c.PublicURL == "" {
		return errors.New("manager public URL is required")
	}
	publicURL, err := url.Parse(c.PublicURL)
	if err != nil || publicURL.Scheme != "https" || publicURL.Hostname() == "" {
		return errors.New("MWAF_PUBLIC_URL must be an https URL")
	}
	if c.EventRetention < 24*time.Hour || c.CleanupInterval < time.Minute || c.PolicySyncInterval < time.Minute || c.CRSSyncInterval < time.Hour {
		return errors.New("event retention must be at least 24h, cleanup and policy sync at least 1m, and CRS sync at least 1h")
	}
	ltsParts := strings.Split(strings.TrimPrefix(c.CRSLTSLine, "v"), ".")
	if len(ltsParts) != 2 || ltsParts[0] != "4" {
		return errors.New("MWAF_CRS_LTS_LINE must be a CRS v4 major.minor line")
	}
	for _, part := range ltsParts {
		if _, err := strconv.Atoi(part); err != nil {
			return errors.New("MWAF_CRS_LTS_LINE must be a CRS v4 major.minor line")
		}
	}
	return nil
}

func validateListenAddress(name, address string) error {
	_, portText, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%s must be a host:port address: %w", name, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("%s port must be between 1 and 65535", name)
	}
	return nil
}

func value(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func boolean(name string, fallback bool) bool {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback
	}
	return v
}

func duration(name string, fallback time.Duration) time.Duration {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback
	}
	v, err := time.ParseDuration(raw)
	if err != nil {
		return fallback
	}
	return v
}

func secret(valueName, fileName, fallback string) (string, error) {
	if path := os.Getenv(fileName); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", fileName, err)
		}
		return strings.TrimSpace(string(raw)), nil
	}
	return value(valueName, fallback), nil
}
