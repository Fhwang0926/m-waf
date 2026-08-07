package manager

import (
	"database/sql"
	"strings"
	"testing"
	"time"
)

func TestNewInstallTokenUsesRecognizableHighEntropyFormat(t *testing.T) {
	first, err := newInstallToken()
	if err != nil {
		t.Fatal(err)
	}
	second, err := newInstallToken()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(first, "mwaf_it_") || len(first) < 48 {
		t.Fatalf("unexpected install token format: %q", first)
	}
	if first == second {
		t.Fatal("install token generator returned a duplicate")
	}
	if prefix := installTokenPrefix(first); !strings.HasPrefix(first, prefix) || len(prefix) != 20 {
		t.Fatalf("unexpected display prefix: %q", prefix)
	}
}

func TestEnterpriseInstallTokenStatus(t *testing.T) {
	active := EnterpriseInstallTokenRecord{ExpiresAt: time.Now().UTC().Add(time.Hour)}
	if !active.Active() || active.StatusLabel() != "활성" {
		t.Fatalf("active token status = %q", active.StatusLabel())
	}
	limited := active
	limited.MaxEnrollments = sql.NullInt64{Int64: 2, Valid: true}
	limited.EnrollmentCount = 2
	if limited.StatusLabel() != "사용 한도 도달" {
		t.Fatalf("limited token status = %q", limited.StatusLabel())
	}
	revoked := active
	revoked.RevokedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}
	if revoked.StatusLabel() != "폐기됨" {
		t.Fatalf("revoked token status = %q", revoked.StatusLabel())
	}
}

func TestInstallTokenParameters(t *testing.T) {
	name, days, maximum, ok := installTokenParameters(" IDC install ", "", "")
	if !ok || name != "IDC install" || days != 30 || maximum != 0 {
		t.Fatalf("defaults = %q %d %d %v", name, days, maximum, ok)
	}
	if _, _, _, ok := installTokenParameters("token", "91", ""); ok {
		t.Fatal("expiry above 90 days was accepted")
	}
	if _, _, _, ok := installTokenParameters("token", "30", "10001"); ok {
		t.Fatal("registration maximum above 10000 was accepted")
	}
}
