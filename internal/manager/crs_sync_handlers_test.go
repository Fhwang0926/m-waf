package manager

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Fhwang0926/m-waf/internal/crssource"
)

func TestCRSSyncFailureExplainsGitHubRateLimit(t *testing.T) {
	now := time.Date(2026, time.August, 9, 16, 11, 36, 0, time.Local)
	resetAt := now.Add(2 * time.Minute)
	server := &Server{}
	failure := server.crsSyncFailure(fmt.Errorf("lts: %w", &crssource.RateLimitError{
		StatusCode: http.StatusForbidden, Limit: 60, Remaining: 0, ResetAt: resetAt,
	}), now)
	if failure.Status != http.StatusServiceUnavailable || failure.RetryAt == "" || failure.RetryIn != 2*time.Minute {
		t.Fatalf("unexpected rate limit presentation: %#v", failure)
	}
	if !strings.Contains(failure.Detail, "MWAF_CRS_GITHUB_TOKEN") || failure.Technical != "" {
		t.Fatalf("rate limit guidance is incomplete: %#v", failure)
	}
	recorder := httptest.NewRecorder()
	setCRSSyncRetryAfter(recorder, failure.RetryIn)
	if recorder.Header().Get("Retry-After") != "120" {
		t.Fatalf("Retry-After = %q, want 120", recorder.Header().Get("Retry-After"))
	}
}

func TestCRSSyncFailurePreservesGenericTechnicalDetail(t *testing.T) {
	server := &Server{}
	failure := server.crsSyncFailure(fmt.Errorf("connection refused"), time.Now())
	if failure.Status != http.StatusBadGateway || failure.Technical != "connection refused" {
		t.Fatalf("unexpected generic presentation: %#v", failure)
	}
}
