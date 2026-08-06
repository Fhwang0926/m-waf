package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAgentExternalIntegrationRequiresAbsoluteBinary(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "agent.json")
	raw := []byte(`{
  "manager_url":"https://manager.example:9443",
  "server_name":"custom-nginx",
  "web_server":"nginx",
  "web_server_binary":"nginx",
  "integration_mode":"external",
  "ca_certificate":"/etc/mwaf-agent/ca.crt",
  "certificate":"/var/lib/mwaf-agent/agent.crt",
  "private_key":"/var/lib/mwaf-agent/agent.key",
  "state_directory":"/var/lib/mwaf-agent",
  "spool_directory":"/var/lib/mwaf-agent/spool",
  "audit_log":"/var/log/modsecurity/audit.jsonl"
}`)
	if err := os.WriteFile(configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAgent(configPath); err == nil {
		t.Fatal("expected a relative custom web-server binary to be rejected")
	}
}

func TestLoadAgentDefaultsToDistroIntegration(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "agent.json")
	raw := []byte(`{
  "manager_url":"https://manager.example:9443",
  "server_name":"distro-nginx",
  "web_server":"nginx",
  "ca_certificate":"/etc/mwaf-agent/ca.crt",
  "certificate":"/var/lib/mwaf-agent/agent.crt",
  "private_key":"/var/lib/mwaf-agent/agent.key",
  "state_directory":"/var/lib/mwaf-agent",
  "spool_directory":"/var/lib/mwaf-agent/spool",
  "audit_log":"/var/log/modsecurity/audit.jsonl"
}`)
	if err := os.WriteFile(configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadAgent(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IntegrationMode != "distro" {
		t.Fatalf("unexpected integration mode %q", cfg.IntegrationMode)
	}
}
