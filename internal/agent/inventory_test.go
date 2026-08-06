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
