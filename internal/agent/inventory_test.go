package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeBuildOutputRemovesRuntimeApacheWarning(t *testing.T) {
	left := normalizeBuildOutput([]byte("AH00558: apache2: hostname 10.0.0.1\n Server version: Apache/2.4.58\n-D APR_HAS_SENDFILE\n"))
	right := normalizeBuildOutput([]byte("AH00558: apache2: hostname 10.0.0.2\nServer version: Apache/2.4.58\n-D APR_HAS_SENDFILE\n"))
	if string(left) != string(right) {
		t.Fatalf("runtime warning changed build identity: %q != %q", left, right)
	}
}

func TestWebServerInfoUsesConfiguredBinary(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "custom-nginx")
	script := []byte("#!/bin/sh\ncase \"$1\" in\n-v) echo 'nginx version: nginx/1.30.4' >&2 ;;\n-V) echo 'nginx version: nginx/1.30.4' >&2; echo 'configure arguments: --prefix=/opt/hosting/nginx' >&2 ;;\n*) exit 2 ;;\nesac\n")
	if err := os.WriteFile(binary, script, 0o700); err != nil {
		t.Fatal(err)
	}
	version, build, err := webServerInfo(context.Background(), "nginx", binary)
	if err != nil {
		t.Fatal(err)
	}
	if version != "1.30.4" || build == "" {
		t.Fatalf("unexpected custom web-server inventory: version=%q build=%q", version, build)
	}
}

func TestInstallationSelectionDefaultsAndValidatesControlMode(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "installation-selection.json")
	legacy := []byte(`{"web_server":"nginx","web_server_binary":"/opt/hosting/nginx","integration_mode":"external","installation_mode":"custom_zip"}`)
	if err := os.WriteFile(path, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	selected, ok := readInstallationSelection(directory)
	if !ok || selected.WebServerControl != "standard" {
		t.Fatalf("legacy selection did not default to standard control: ok=%v selection=%#v", ok, selected)
	}
	invalid := []byte(`{"web_server":"nginx","web_server_binary":"/opt/hosting/nginx","web_server_control":"shell","integration_mode":"external","installation_mode":"custom_zip"}`)
	if err := os.WriteFile(path, invalid, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := readInstallationSelection(directory); ok {
		t.Fatal("arbitrary web-server control mode was accepted")
	}
}

func TestControlHookPathsStayUnderOptMWAF(t *testing.T) {
	if got := controlHookPath("apache", "reload"); got != "/opt/m-waf/hooks/apache/reload" {
		t.Fatalf("unexpected hook path %q", got)
	}
}

func TestAgentCanReturnInstalledServerToStandardControl(t *testing.T) {
	directory := t.TempDir()
	selection := []byte(`{"web_server":"apache","web_server_binary":"/opt/hosting/apachectl","web_server_control":"hooks","integration_mode":"external","installation_mode":"custom_zip"}`)
	if err := os.WriteFile(filepath.Join(directory, "installation-selection.json"), selection, 0o600); err != nil {
		t.Fatal(err)
	}
	agent := Agent{}
	agent.cfg.StateDirectory = directory
	handled, _, err := agent.applyWebServerControlCommand("web_control_standard")
	if err != nil || !handled {
		t.Fatalf("standard control command failed: handled=%v err=%v", handled, err)
	}
	updated, ok := readInstallationSelection(directory)
	if !ok || updated.WebServerControl != "standard" {
		t.Fatalf("control mode was not updated: ok=%v selection=%#v", ok, updated)
	}
}
