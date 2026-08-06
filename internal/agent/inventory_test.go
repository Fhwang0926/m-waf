package agent

import "testing"

func TestNormalizeBuildOutputRemovesRuntimeApacheWarning(t *testing.T) {
	left := normalizeBuildOutput([]byte("AH00558: apache2: hostname 10.0.0.1\n Server version: Apache/2.4.58\n-D APR_HAS_SENDFILE\n"))
	right := normalizeBuildOutput([]byte("AH00558: apache2: hostname 10.0.0.2\nServer version: Apache/2.4.58\n-D APR_HAS_SENDFILE\n"))
	if string(left) != string(right) {
		t.Fatalf("runtime warning changed build identity: %q != %q", left, right)
	}
}
